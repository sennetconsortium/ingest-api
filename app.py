import os
import sys
import logging
import urllib.request
import requests
import re
import json
from uuid import UUID
import yaml
import csv
import requests
from hubmap_sdk import EntitySdk
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
from pathlib import Path
from shutil import rmtree # Used by file removal
from flask import Flask, g, jsonify, abort, request, session, redirect, json, Response
from flask_cors import CORS
from globus_sdk import AccessTokenAuthorizer, AuthClient, ConfidentialAppAuthClient

# HuBMAP commons
from hubmap_commons import neo4j_driver
from hubmap_commons.hm_auth import AuthHelper, secured
from hubmap_commons.autherror import AuthError
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import string_helper
from hubmap_commons.string_helper import isBlank
from hubmap_commons import net_helper
from hubmap_commons import file_helper as commons_file_helper

# Should be deprecated/refactored but still in use
from hubmap_commons.hubmap_const import HubmapConst

# Local modules
from specimen import Specimen
from ingest_file_helper import IngestFileHelper
from file_upload_helper import UploadFileHelper
import app_manager
from dataset import Dataset
from dataset_helper_object import DatasetHelper

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config=True)
app.config.from_pyfile('app.cfg')

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
requests.packages.urllib3.disable_warnings(category = InsecureRequestWarning)

# Enable/disable CORS from configuration based on docker or non-docker deployment
if app.config['ENABLE_CORS']:
    CORS(app)

####################################################################################################
## Register error handlers
####################################################################################################

# Error handler for 400 Bad Request with custom error message
@app.errorhandler(400)
def http_bad_request(e):
    return jsonify(error=str(e)), 400

# Error handler for 401 Unauthorized with custom error message
@app.errorhandler(401)
def http_unauthorized(e):
    return jsonify(error=str(e)), 401

# Error handler for 404 Not Found with custom error message
@app.errorhandler(404)
def http_not_found(e):
    return jsonify(error=str(e)), 404

# Error handler for 500 Internal Server Error with custom error message
@app.errorhandler(500)
def http_internal_server_error(e):
    return jsonify(error=str(e)), 500


####################################################################################################
## AuthHelper initialization
####################################################################################################

# Initialize AuthHelper class and ensure singleton
try:
    if AuthHelper.isInitialized() == False:
        auth_helper_instance = AuthHelper.create(app.config['APP_CLIENT_ID'],
                                                 app.config['APP_CLIENT_SECRET'])

        logger.info("Initialized AuthHelper class successfully :)")
    else:
        auth_helper_instance = AuthHelper.instance()
except Exception:
    msg = "Failed to initialize the AuthHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)


####################################################################################################
## Neo4j connection initialization
####################################################################################################

# The neo4j_driver (from commons package) is a singleton module
# This neo4j_driver_instance will be used for application-specific neo4j queries
# as well as being passed to the schema_manager
try:
    neo4j_driver_instance = neo4j_driver.instance(app.config['NEO4J_SERVER'],
                                                  app.config['NEO4J_USERNAME'],
                                                  app.config['NEO4J_PASSWORD'])

    logger.info("Initialized neo4j_driver module successfully :)")
except Exception:
    msg = "Failed to initialize the neo4j_driver module"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)


"""
Close the current neo4j connection at the end of every request
"""
@app.teardown_appcontext
def close_neo4j_driver(error):
    if hasattr(g, 'neo4j_driver_instance'):
        # Close the driver instance
        neo4j_driver.close()
        # Also remove neo4j_driver_instance from Flask's application context
        g.neo4j_driver_instance = None


####################################################################################################
## File upload initialization
####################################################################################################

try:
    # Initialize the UploadFileHelper class and ensure singleton
    if UploadFileHelper.is_initialized() == False:
        file_upload_helper_instance = UploadFileHelper.create(app.config['FILE_UPLOAD_TEMP_DIR'],
                                                              app.config['FILE_UPLOAD_DIR'],
                                                              app.config['UUID_WEBSERVICE_URL'])

        logger.info("Initialized UploadFileHelper class successfully :)")

        # This will delete all the temp dirs on restart
        #file_upload_helper_instance.clean_temp_dir()
    else:
        file_upload_helper_instance = UploadFileHelper.instance()
# Use a broad catch-all here
except Exception:
    msg = "Failed to initialize the UploadFileHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)

# Admin group UUID
data_admin_group_uuid = app.config['HUBMAP_DATA_ADMIN_GROUP_UUID']
data_curator_group_uuid = app.config['HUBMAP_DATA_CURATOR_GROUP_UUID']

####################################################################################################
## Default and Status Routes
####################################################################################################

@app.route('/', methods = ['GET'])
def index():
    return "Hello! This is HuBMAP Ingest API service :)"

# Show status of neo4j connection and optionally of the dependent web services
# to show the status of the other hubmap services that ingest-api is dependent on
# use the url parameter "?check-ws-dependencies=true
# returns a json body with the status of the neo4j service and optionally the
# status/time that it took for the dependent web services to respond
# e.g.:
#     {
#        "build": "adfadsfasf",
#        "entity_ws": 130,
#        "neo4j_connection": true,
#        "search_ws_check": 127,
#        "uuid_ws": 105,
#        "version": "1.15.4"
#     }
@app.route('/status', methods = ['GET'])
def status():
    response_code = 200
    response_data = {
        # Use strip() to remove leading and trailing spaces, newlines, and tabs
        'version': (Path(__file__).absolute().parent.parent / 'VERSION').read_text().strip(),
        'build': (Path(__file__).absolute().parent.parent / 'BUILD').read_text().strip(),
    }

    try:
        #if ?check-ws-dependencies=true is present in the url request params
        #set a flag to check these other web services
        check_ws_calls = string_helper.isYes(request.args.get('check-ws-dependencies'))

        #check the neo4j connection
        try:
            with neo4j_driver_instance.session() as session:
                recds = session.run("Match () Return 1 Limit 1")
                for recd in recds:
                    if recd[0] == 1:
                        is_connected = True
                    else:
                        is_connected = False

                is_connected = True
        #the neo4j connection will often fail via exception so
        #catch it here, flag as failure and track the returned error message
        except Exception as e:
            response_code = 500
            response_data['neo4j_error'] = str(e)
            is_connected = False

        if is_connected:
            response_data['neo4j_connection'] = True
        else:
            response_code = 500
            response_data['neo4j_connection'] = False

        #if the flag was set to check ws dependencies do it now
        #for each dependency try to connect via helper which calls the
        #service's /status method
        #The helper method will return False if the connection fails or
        #an integer with the number of milliseconds that it took to get
        #the services status
        if check_ws_calls:
            uuid_ws_url = app.config['UUID_WEBSERVICE_URL'].strip()
            if uuid_ws_url.endswith('hmuuid'): uuid_ws_url = uuid_ws_url[:len(uuid_ws_url) - 6]
            uuid_ws_check = net_helper.check_hm_ws(uuid_ws_url)
            entity_ws_check = net_helper.check_hm_ws(app.config['ENTITY_WEBSERVICE_URL'])
            search_ws_check = net_helper.check_hm_ws(app.config['SEARCH_WEBSERVICE_URL'])
            if not uuid_ws_check or not entity_ws_check or not search_ws_check: response_code = 500
            response_data['uuid_ws'] = uuid_ws_check
            response_data['entity_ws'] = entity_ws_check
            response_data['search_ws_check'] = search_ws_check

    #catch any unhandled exceptions
    except Exception as e:
        response_code = 500
        response_data['exception_message'] = str(e)
    finally:
        return Response(json.dumps(response_data), response_code, mimetype='application/json')

####################################################################################################
## Endpoints for UI Login and Logout
####################################################################################################

# Redirect users from react app login page to Globus auth login widget then redirect back
@app.route('/login')
def login():
    #redirect_uri = url_for('login', _external=True)
    redirect_uri = app.config['FLASK_APP_BASE_URI'] + 'login'

    confidential_app_auth_client = ConfidentialAppAuthClient(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
    confidential_app_auth_client.oauth2_start_flow(redirect_uri, refresh_tokens=True)

    # If there's no "code" query string parameter, we're in this route
    # starting a Globus Auth login flow.
    # Redirect out to Globus Auth
    if 'code' not in request.args:
        auth_uri = confidential_app_auth_client.oauth2_get_authorize_url(additional_params={"scope": "openid profile email urn:globus:auth:scope:transfer.api.globus.org:all urn:globus:auth:scope:auth.globus.org:view_identities urn:globus:auth:scope:nexus.api.globus.org:groups urn:globus:auth:scope:groups.api.globus.org:all" })
        return redirect(auth_uri)
    # If we do have a "code" param, we're coming back from Globus Auth
    # and can start the process of exchanging an auth code for a token.
    else:
        auth_code = request.args.get('code')

        token_response = confidential_app_auth_client.oauth2_exchange_code_for_tokens(auth_code)

        # Get all Bearer tokens
        auth_token = token_response.by_resource_server['auth.globus.org']['access_token']
        #nexus_token = token_response.by_resource_server['nexus.api.globus.org']['access_token']
        transfer_token = token_response.by_resource_server['transfer.api.globus.org']['access_token']
        groups_token = token_response.by_resource_server['groups.api.globus.org']['access_token']
        # Also get the user info (sub, email, name, preferred_username) using the AuthClient with the auth token
        user_info = get_user_info(auth_token)

        info = {
            'name': user_info['name'],
            'email': user_info['email'],
            'globus_id': user_info['sub'],
            'auth_token': auth_token,
            #'nexus_token': nexus_token,
            'transfer_token': transfer_token,
            'groups_token': groups_token
        }

        # Turns json dict into a str
        json_str = json.dumps(info)
        #print(json_str)

        # Store the resulting tokens in server session
        session.update(
            tokens=token_response.by_resource_server
        )

        # Finally redirect back to the client
        return redirect(app.config['GLOBUS_CLIENT_APP_URI'] + '?info=' + str(json_str))

@app.route('/logout')
def logout():
    """
    - Revoke the tokens with Globus Auth.
    - Destroy the session state.
    - Redirect the user to the Globus Auth logout page.
    """
    confidential_app_auth_client = ConfidentialAppAuthClient(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])

    # Revoke the tokens with Globus Auth
    if 'tokens' in session:
        for token in (token_info['access_token']
            for token_info in session['tokens'].values()):
                confidential_app_auth_client.oauth2_revoke_token(token)

    # Destroy the session state
    session.clear()

    # build the logout URI with query params
    # there is no tool to help build this (yet!)
    globus_logout_url = (
        'https://auth.globus.org/v2/web/logout' +
        '?client={}'.format(app.config['APP_CLIENT_ID']) +
        '&redirect_uri={}'.format(app.config['GLOBUS_CLIENT_APP_URI']) +
        '&redirect_name={}'.format(app.config['GLOBUS_CLIENT_APP_NAME']))

    # Redirect the user to the Globus Auth logout page
    return redirect(globus_logout_url)


####################################################################################################
## Register error handlers
####################################################################################################

# Error handler for 400 Bad Request with custom error message
@app.errorhandler(400)
def http_bad_request(e):
    return jsonify(error=str(e)), 400

# Error handler for 500 Internal Server Error with custom error message
@app.errorhandler(500)
def http_internal_server_error(e):
    return jsonify(error=str(e)), 500


####################################################################################################
## Ingest API Endpoints
####################################################################################################

@app.route('/datasets', methods=['POST'])
def create_datastage():
    if not request.is_json:
        return Response("json request required", 400)
    try:
        dataset_request = request.json
        auth_helper = AuthHelper.configured_instance(app.config['APP_CLIENT_ID'], app.config['APP_CLIENT_SECRET'])
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        if isinstance(auth_tokens, Response):
            return(auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        elif 'nexus_token' in auth_tokens:
            token = auth_tokens['nexus_token']
        else:
            return(Response("Valid nexus auth token required", 401))

        requested_group_uuid = None
        if 'group_uuid' in dataset_request:
            requested_group_uuid = dataset_request['group_uuid']

        ingest_helper = IngestFileHelper(app.config)
        requested_group_uuid = auth_helper.get_write_group_uuid(token, requested_group_uuid)
        dataset_request['group_uuid'] = requested_group_uuid
        post_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/dataset'
        response = requests.post(post_url, json = dataset_request, headers = {'Authorization': 'Bearer ' + token, 'X-Hubmap-Application':'ingest-api' }, verify = False)
        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_dataset = response.json()

        ingest_helper.create_dataset_directory(new_dataset, requested_group_uuid, new_dataset['uuid'])

        return jsonify(new_dataset)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)

####################################################################################################
## Uploads API Endpoints
####################################################################################################

def validate_samples(headers, records, header):
    error_msg = []
    file_is_valid = True
    # if not 'source_id' in headers:
    #     file_is_valid = False
    #     error_msg.append("source_id field is required")
    # if not 'lab_id' in headers:
    #     file_is_valid = False
    #     error_msg.append("lab_id field is required")
    # if not 'sample_type' in headers:
    #     file_is_valid = False
    #     error_msg.append("sample_type field is required")
    # if not 'organ_type' in headers:
    #     file_is_valid = False
    # if not 'sample_protocol' in headers:
    #     file_is_valid = False
    #     error_msg.append("sample_protocol field is required")
    # if not 'description' in headers:
    #     file_is_valid = False
    #     error_msg.append("sample_protocol field is required")
    # if not 'rui_location' in headers:
    #     file_is_valid = False
    #     error_msg.append("rui_location field is required")

    required_headers = ['source_id', 'lab_id', 'sample_type', 'organ_type', 'sample_protocol', 'description', 'rui_location']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(f"{field} is a required field")
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(f"{field} is not an accepted field")

    with urllib.request.urlopen(
            'https://raw.githubusercontent.com/hubmapconsortium/search-api/master/src/search-schema/data/definitions/enums/tissue_sample_types.yaml') as urlfile:
        sample_resource_file = yaml.load(urlfile, Loader=yaml.FullLoader)

    with urllib.request.urlopen(
            'https://raw.githubusercontent.com/hubmapconsortium/search-api/master/src/search-schema/data/definitions/enums/organ_types.yaml') as urlfile:
        organ_resource_file = yaml.load(urlfile, Loader=yaml.FullLoader)

    rownum = 1
    valid_source_ids = []
    if file_is_valid is True:
        for data_row in records:

            # validate rui_location
            rui_is_blank = True
            rui_location = data_row['rui_location']
            if len(rui_location) > 0:
                rui_is_blank = False
                if "\n" in rui_location:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. rui_location must contain no line breaks")
                try:
                    rui_location_dict = json.loads(rui_location)
                except:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. rui_location must be a valid json file")

            # validate sample_type
            sample_type = data_row['sample_type']
            if rui_is_blank is False and sample_type.lower() == 'organ':
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. If rui_location field is not blank, sample type cannot be organ")
            if sample_type.lower() not in sample_resource_file:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. sample_type value must be a sample code listed in tissue sample type files (https://raw.githubusercontent.com/hubmapconsortium/search-api/master/src/search-schema/data/definitions/enums/tissue_sample_types.yaml)")

            # validate organ_type
            organ_type = data_row['organ_type']
            if sample_type.lower() != "organ":
                if len(organ_type) > 0:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. organ_type field must be blank if sample_type is not 'organ'")
            if sample_type.lower() == "organ":
                if len(organ_type) < 1:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. organ_type field is required if sample_type is 'organ'")
            if len(organ_type) > 0:
                if organ_type.upper() not in organ_resource_file:
                    file_is_valid = False
                    error_msg.append(
                        f"Row Number: {rownum}. organ_type value must be a sample code listed in tissue sample type files (https://raw.githubusercontent.com/hubmapconsortium/search-api/master/src/search-schema/data/definitions/enums/organ_types.yaml)")

            # validate description
            description = data_row['description']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. Description must be fewer than 10,000 characters")

            # validate sample_protocol
            protocol = data_row['sample_protocol']
            selection_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\.[\w]*', protocol)
            selection_protocol_pattern2 = re.match('^[\d]+\.[\d]+/protocols\.io\.[\w]*', protocol)
            if selection_protocol_pattern2 is None and selection_protocol_pattern1 is None:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. sample_protocol must either be of the format https://dx.doi.org/##.####/protocols.io.* or ##.####/protocols.io.*")
            if len(protocol) < 1:
                file_is_valid = False
                error_msg.append(f"row Number: {rownum}. sample_protocol is a required filed and cannot be blank.")

            # validate lab_id
            lab_id = data_row['lab_id']
            # lab_id_pattern = re.match('^\w*$', lab_id)
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id must be fewer than 1024 characters")
            # if lab_id_pattern is None:
            #     file_is_valid = False
            #     error_msg.append(f"Row Number: {rownum}. if lab_id is given, it must be an alphanumeric string")
            if len(lab_id) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id value cannot be blank")

            # validate source_id
            source_id = data_row['source_id']
            # hubmap_id_pattern = re.match('[A-Z]{3}[\d]{3}\.[A-Z]{4}\.[\d]{3}', source_id)
            # hubmap_uuid_pattern = re.match('([a-f]|[0-9]){32}', source_id)
            # hubmap_doi_pattern = re.match('[\d]{2}\.[\d]{4}/[A-Z]{3}[\d]{3}\.[A-Z]{4}\.[\d]{3}', source_id)
            if len(source_id) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. source_id cannot be blank")
            if len(source_id) > 0:
                source_dict = {}
                source_saved = False
                resp_status_code = False
                if len(valid_source_ids) > 0:
                    for item in valid_source_ids:
                        if item['hm_uuid'] or item['hubmap_id']:
                            if source_id == item['hm_uuid'] or source_id == item['hubmap_id']:
                                source_dict = item
                                source_saved = True
                if source_saved is False:
                    url = commons_file_helper.ensureTrailingSlashURL(app.config['UUID_WEBSERVICE_URL']) + source_id
                    # url = "https://uuid-api.dev.hubmapconsortium.org/hmuuid/" + source_id
                    resp = requests.get(url, headers=header)
                    if resp.status_code == 404:
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. Unable to verify source_id exists")
                    if resp.status_code == 401:
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. Unauthorized. Cannot access UUID-api")
                    if resp.status_code == 400:
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. {source_id} is not a valid id format")
                    if resp.status_code < 300:
                        source_dict = resp.json()
                        valid_source_ids.append(source_dict)
                        resp_status_code = True
                if source_saved or resp_status_code:
                    data_row['source_id'] = source_dict['hm_uuid']
                    if sample_type.lower() == 'organ' and source_dict['type'].lower() != 'donor':
                        file_is_valid = False
                        error_msg.append(
                            f"Row Number: {rownum}. If sample type is organ, source_id must point to a donor")
                    if sample_type.lower() != 'organ' and source_dict['type'].lower() != 'sample':
                        file_is_valid = False
                        error_msg.append(
                            f"Row Number: {rownum}. If sample type is not organ, source_id must point to a sample")
                    if rui_is_blank is False and source_dict['type'].lower() == 'donor':
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. If rui_location is blank, source_id cannot be a donor")

            rownum = rownum + 1

    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg


#Validates a bulk tsv file containing multiple donors. A valid tsv of donors must have certain fields, and all fields have certain accepted values. Returns "true" if valid. If invalid, returns a list of strings of various error messages
def validate_donors(headers, records):
    error_msg = []
    file_is_valid = True
    # if not 'lab_name' in headers:
    #     file_is_valid = False
    #     error_msg.append("lab_name field is required")
    # if not 'selection_protocol' in headers:
    #     file_is_valid = False
    #     error_msg.append("selection_protocol field is required")
    # if not 'description' in headers:
    #     file_is_valid = False
    #     error_msg.append("description field is required")
    # if not 'lab_id' in headers:
    #     file_is_valid = False
    #     error_msg.append("lab_id field is required") #if any of this fails, just stop

    required_headers = ['lab_name', 'selection_protocol', 'description', 'lab_id']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(f"{field} is a required field")
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(f"{field} is not an accepted field")
    rownum = 1
    if file_is_valid is True:
        for data_row in records:

            #validate lab_name
            if len(data_row['lab_name']) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_name must be fewer than 1024 characters")
            if len(data_row['lab_name']) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_name must have 1 or more characters")
            # lab_name_pattern = re.match('^\w*$')
            # if lab_name_pattern == None:
            #     file_is_valid = False
            #     error_msg.append(f"Row Number: {rownum}. lab_name must be an alphanumeric string")

            #validate selection_protocol
            protocol = data_row['selection_protocol']
            selection_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\.[\w]*', protocol)
            selection_protocol_pattern2 = re.match('^[\d]+\.[\d]+/protocols\.io\.[\w]*', protocol)
            if selection_protocol_pattern2 is None and selection_protocol_pattern1 is None:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. selection_protocol must either be of the format https://dx.doi.org/##.####/protocols.io.* or ##.####/protocols.io.*")

            #validate description
            description = data_row['description']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. Description must be fewer than 10,000 characters")

            #validate lab_id
            lab_id = data_row['lab_id']
            #lab_id_pattern = re.match('^\w*$', lab_id)
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id must be fewer than 1024 characters")
            #if lab_id_pattern is None:
            #    file_is_valid = False
            #    error_msg.append(f"Row Number: {rownum}. if lab_id is given, it must be an alphanumeric string")
            rownum = rownum + 1

    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg

####################################################################################################
## Internal Functions
####################################################################################################

"""
Always expect a json body from user request

request : Flask request object
    The Flask request passed from the API endpoint
"""
def require_json(request):
    if not request.is_json:
        bad_request_error("A json body and appropriate Content-Type header are required")

"""
Throws error for 400 Bad Reqeust with message
Parameters
----------
err_msg : str
    The custom error message to return to end users
"""
def bad_request_error(err_msg):
    abort(400, description = err_msg)

"""
Throws error for 401 Unauthorized with message
Parameters
----------
err_msg : str
    The custom error message to return to end users
"""
def unauthorized_error(err_msg):
    abort(401, description = err_msg)

"""
Throws error for 404 Not Found with message
Parameters
----------
err_msg : str
    The custom error message to return to end users
"""
def not_found_error(err_msg):
    abort(404, description = err_msg)

"""
Throws error for 500 Internal Server Error with message
Parameters
----------
err_msg : str
    The custom error message to return to end users
"""
def internal_server_error(err_msg):
    abort(500, description = err_msg)
    

def get_user_info(token):
    auth_client = AuthClient(authorizer=AccessTokenAuthorizer(token))
    return auth_client.oauth2_userinfo()

def __get_dict_prop(dic, prop_name):
    if not prop_name in dic: return None
    val = dic[prop_name]
    if isinstance(val, str) and val.strip() == '': return None
    return val

def __get_entity(entity_uuid, auth_header = None):
    if auth_header is None:
        headers = None
    else:
        headers = {'Authorization': auth_header, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    get_url = commons_file_helper.ensureTrailingSlashURL(app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + entity_uuid

    response = requests.get(get_url, headers = headers, verify = False)
    if response.status_code != 200:
        err_msg = f"Error while calling {get_url} status code:{response.status_code}  message:{response.text}"
        logger.error(err_msg)
        raise HTTPException(err_msg, response.status_code)

    return response.json()

# Determines if a dataset is Primary. If the list returned from the neo4j query is empty, the dataset is not primary
def dataset_is_primary(dataset_uuid):
    with neo4j_driver_instance.session() as neo_session:
        q = (f"MATCH (ds:Dataset {{uuid: '{dataset_uuid}'}})<-[:ACTIVITY_OUTPUT]-(:Activity)<-[:ACTIVITY_INPUT]-(s:Sample) RETURN ds.uuid")
        result = neo_session.run(q).data()
        if len(result) == 0:
            return False
        return True


# For local development/testing
if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port")
        args = parser.parse_args()
        port = 8484
        if args.port:
            port = int(args.port)
        app.run(port=port, host='0.0.0.0')
    finally:
        pass
