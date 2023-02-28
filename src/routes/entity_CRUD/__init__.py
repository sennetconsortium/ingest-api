import sys

from flask import Blueprint, jsonify, request, Response, current_app, abort, json
import logging
import requests
import os
import csv
import re
import urllib.request
import yaml
from werkzeug import utils
from operator import itemgetter

from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper

entity_CRUD_blueprint = Blueprint('entity_CRUD', __name__)
logger = logging.getLogger(__name__)

# Local modules
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper
from routes.entity_CRUD.file_upload_helper import UploadFileHelper
from routes.entity_CRUD.dataset_helper import DatasetHelper
from routes.entity_CRUD.constraints_helper import *


@entity_CRUD_blueprint.route('/datasets', methods=['POST'])
def create_dataset():

    if not request.is_json:
        return Response("json request required", 400)
    try:
        dataset_request = request.json
        # Get the single Globus groups token for authorization
        auth_helper_instance = AuthHelper.instance()
        auth_token = auth_helper_instance.getAuthorizationTokens(request.headers)
        if isinstance(auth_token, Response):
            return(auth_token)
        elif isinstance(auth_token, str):
            token = auth_token
        else:
            return Response("Valid Globus groups token required", 401)

        requested_group_uuid = None
        if 'group_uuid' in dataset_request:
            requested_group_uuid = dataset_request['group_uuid']

        ingest_helper = IngestFileHelper(current_app.config)
        requested_group_uuid = auth_helper_instance.get_write_group_uuid(token, requested_group_uuid)
        dataset_request['group_uuid'] = requested_group_uuid
        post_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/dataset'
        response = requests.post(post_url, json = dataset_request, headers = {'Authorization': 'Bearer ' + token, 'X-SenNet-Application':'ingest-api' }, verify = False)
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


@entity_CRUD_blueprint.route('/datasets/<identifier>/publish', methods=['PUT'])
def publish_datastage(identifier):
    try:
        auth_helper_instance = AuthHelper.instance()
        dataset_helper = DatasetHelper(current_app.config)

        user_info = auth_helper_instance.getUserInfoUsingRequest(request, getGroups=True)
        if user_info is None:
            return Response("Unable to obtain user information for auth token", 401)
        if isinstance(user_info, Response):
            return user_info

        if 'hmgroupids' not in user_info:
            return Response("User has no valid group information to authorize publication.", 403)
        if not auth_helper_instance.has_data_admin_privs(auth_helper_instance.getUserTokenFromRequest(request, getGroups=True)):
            return Response("User must be a member of the SenNet Data Admin group to publish data.", 403)

        if identifier is None or len(identifier) == 0:
            abort(400, jsonify({'error': 'identifier parameter is required to publish a dataset'}))
        r = requests.get(current_app.config['UUID_WEBSERVICE_URL'] + "/uuid/" + identifier,
                         headers={'Authorization': request.headers["AUTHORIZATION"]})
        if r.ok is False:
            raise ValueError("Cannot find specimen with identifier: " + identifier)
        dataset_uuid = json.loads(r.text)['hm_uuid']

        return dataset_helper.determine_sources_to_reindex(identifier, user_info, dataset_uuid)

    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)


@entity_CRUD_blueprint.route('/sources/bulk-upload', methods=['POST'])
def bulk_sources_upload_and_validate():
    file_upload_helper_instance: UploadFileHelper = UploadFileHelper.instance()
    if 'file' not in request.files:
        bad_request_error('No file part')
    file = request.files['file']
    if file.filename == '':
        bad_request_error('No selected file')
    file.filename = file.filename.replace(" ", "_")
    try:
        temp_id = file_upload_helper_instance.save_temp_file(file)
    except Exception as e:
        bad_request_error(f"Failed to create temp_id: {e}")
    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    records = []
    headers = []
    file.filename = utils.secure_filename(file.filename)
    file_location = commons_file_helper.ensureTrailingSlash(current_app.config['FILE_UPLOAD_TEMP_DIR']) + temp_id + os.sep + file.filename
    with open(file_location, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    validfile = validate_sources(headers, records)
    if validfile == True:
        return Response(json.dumps({'temp_id': temp_id}, sort_keys=True), 201, mimetype='application/json')
    if type(validfile) == list:
        response_body = {"status": "fail", "data": validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400,
                        mimetype='application/json')  # The exact format of the return to be determined
    else:
        message = f'Unexpected error occurred while validating tsv file. Expecting validfile to be of type List or Boolean but got type {type(validfile)}'
        response_body = {"status": "fail", "message": message}
        return Response(json.dumps(response_body, sort_keys=True), 500, mimetype='application/json')


@entity_CRUD_blueprint.route('/sources/bulk', methods=['POST'])
def create_sources_from_bulk():
    request_data = request.get_json()
    auth_helper_instance = AuthHelper.instance()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    try:
        temp_id = request_data['temp_id']
    except KeyError:
        return_body = {"status": "fail", "message": f"No key 'temp_id' in request body"}
        return Response(json.dumps(return_body, sort_keys=True), 400, mimetype='application/json')
    group_uuid = None
    if "group_uuid" in request_data:
        group_uuid = request_data['group_uuid']
    temp_dir = current_app.config['FILE_UPLOAD_TEMP_DIR']
    tsv_directory = commons_file_helper.ensureTrailingSlash(temp_dir) + temp_id + os.sep
    if not os.path.exists(tsv_directory):
        return_body = {"status": "fail", "message": f"Temporary file with id {temp_id} does not have a temp directory"}
        return Response(json.dumps(return_body, sort_keys=True), 400, mimetype='application/json')
    fcount = 0
    temp_file_name = None
    for tfile in os.listdir(tsv_directory):
        fcount = fcount + 1
        temp_file_name = tfile
    if fcount == 0:
        return Response(json.dumps({"status": "fail", "message": f"File not found in temporary directory /{temp_id}"},
                                   sort_keys=True), 400, mimetype='application/json')
    if fcount > 1:
        return Response(
            json.dumps({"status": "fail", "message": f"Multiple files found in temporary file path /{temp_id}"},
                       sort_keys=True), 400, mimetype='application/json')
    tsvfile_name = tsv_directory + temp_file_name
    records = []
    headers = []
    with open(tsvfile_name, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    validfile = validate_sources(headers, records)

    if type(validfile) == list:
        return_validfile = {}
        error_num = 0
        for item in validfile:
            return_validfile[str(error_num)] = str(item)
            error_num = error_num + 1
        response_body = {"status": "fail", "data": return_validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400, mimetype='application/json')
    entity_response = {}
    row_num = 1
    if validfile == True:
        entity_created = False
        entity_failed_to_create = False
        for item in records:
            item['lab_source_id'] = item['lab_id']
            del item['lab_id']
            item['protocol_url'] = item['selection_protocol']
            del item['selection_protocol']
            item['description'] = item['lab_notes']
            del item['lab_notes']
            if group_uuid is not None:
                item['group_uuid'] = group_uuid
            r = requests.post(
                commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/source',
                headers=header, json=item)
            entity_response[row_num] = r.json()
            row_num = row_num + 1
            status_code = r.status_code
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                entity_created = True
        return _send_response_on_file(entity_created, entity_failed_to_create, entity_response)


@entity_CRUD_blueprint.route('/samples/bulk-upload', methods=['POST'])
def bulk_samples_upload_and_validate():
    file_upload_helper_instance: UploadFileHelper = UploadFileHelper.instance()
    auth_helper_instance = AuthHelper.instance()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    if 'file' not in request.files:
        bad_request_error('No file part')
    file = request.files['file']
    if file.filename == '':
        bad_request_error('No selected file')
    file.filename = file.filename.replace(" ", "_")
    try:
        temp_id = file_upload_helper_instance.save_temp_file(file)
    except Exception as e:
        bad_request_error(f"Failed to create temp_id: {e}")
    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    records = []
    headers = []
    file.filename = utils.secure_filename(file.filename)
    file_location = commons_file_helper.ensureTrailingSlash(
        current_app.config['FILE_UPLOAD_TEMP_DIR']) + temp_id + os.sep + file.filename
    with open(file_location, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    validfile = validate_samples(headers, records, header)
    if validfile == True:
        return Response(json.dumps({'temp_id': temp_id}, sort_keys=True), 201, mimetype='application/json')
    if type(validfile) == list:
        response_body = {"status": "fail", "data": validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400, mimetype='application/json')
    else:
        message = f'Unexpected error occurred while validating tsv file. Expecting validfile to be of type List or Boolean but got type {type(validfile)}'
        response_body = {"status": "fail", "message": message}
        return Response(json.dumps(response_body, sort_keys=True), 500, mimetype='application/json')


@entity_CRUD_blueprint.route('/samples/bulk', methods=['POST'])
def create_samples_from_bulk():
    request_data = request.get_json()
    auth_helper_instance = AuthHelper.instance()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    try:
        temp_id = request_data['temp_id']
    except KeyError:
        return_body = {"status": "fail", "message": f"No key 'temp_id' in request body"}
        return Response(json.dumps(return_body, sort_keys=True), 400, mimetype='application/json')
    group_uuid = None
    if "group_uuid" in request_data:
        group_uuid = request_data['group_uuid']
    temp_dir = current_app.config['FILE_UPLOAD_TEMP_DIR']
    tsv_directory = commons_file_helper.ensureTrailingSlash(temp_dir) + temp_id + os.sep
    if not os.path.exists(tsv_directory):
        return_body = {"status": "fail", "message": f"Temporary file with id {temp_id} does not have a temp directory"}
        return Response(json.dumps(return_body, sort_keys=True), 400, mimetype='application/json')
    fcount = 0
    temp_file_name = None
    for tfile in os.listdir(tsv_directory):
        fcount = fcount + 1
        temp_file_name = tfile
    if fcount == 0:
        return Response(json.dumps({"status": "fail", "message": f"File not found in temporary directory /{temp_id}"},
                                   sort_keys=True), 400, mimetype='application/json')
    if fcount > 1:
        return Response(
            json.dumps({"status": "fail", "message": f"Multiple files found in temporary file path /{temp_id}"},
                       sort_keys=True), 400, mimetype='application/json')
    tsvfile_name = tsv_directory + temp_file_name
    records = []
    headers = []
    with open(tsvfile_name, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    validfile = validate_samples(headers, records, header)

    if type(validfile) == list:
        response_body = {"status": False, "data": validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400, mimetype='application/json')
    entity_response = {}
    row_num = 1
    if validfile == True:
        entity_created = False
        entity_failed_to_create = False
        for item in records:
            item['direct_ancestor_uuid'] = item['ancestor_id']
            del item['ancestor_id']
            item['lab_tissue_sample_id'] = item['lab_id']
            del item['lab_id']
            item['description'] = item['lab_notes']
            del item['lab_notes']
            item['protocol_url'] = item['preparation_protocol']
            del item['preparation_protocol']
            item['organ'] = item['organ_type']
            del item['organ_type']
            if item['organ'] == '':
                del item['organ']
            if group_uuid is not None:
                item['group_uuid'] = group_uuid
            r = requests.post(
                commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/sample',
                headers=header, json=item)
            entity_response[row_num] = r.json()
            row_num = row_num + 1
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                entity_created = True
        return _send_response_on_file(entity_created, entity_failed_to_create, entity_response)


@entity_CRUD_blueprint.route('/datasets/bulk-upload', methods=['POST'])
def bulk_datasets_upload_and_validate():
    file_upload_helper_instance: UploadFileHelper = UploadFileHelper.instance()
    auth_helper_instance = AuthHelper.instance()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token}
    if 'file' not in request.files:
        bad_request_error('No file part')
    file = request.files['file']
    if file.filename == '':
        bad_request_error('No selected file')
    file.filename = file.filename.replace(" ", "_")
    try:
        temp_id = file_upload_helper_instance.save_temp_file(file)
    except Exception as e:
        bad_request_error(f"Failed to create temp_id: {e}")
    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    records = []
    headers = []
    file.filename = utils.secure_filename(file.filename)
    file_location = commons_file_helper.ensureTrailingSlash(
        current_app.config['FILE_UPLOAD_TEMP_DIR']) + temp_id + os.sep + file.filename
    with open(file_location, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    # Ancestor_id and data_types can contain multiple entries each. These must be split by comma before validating
    for record in records:
        if record.get('ancestor_id'):
            ancestor_id_string = record['ancestor_id']
            ancestor_id_list = ancestor_id_string.split(',')
            if isinstance(ancestor_id_list, str):
                ancestor_id_list = [ancestor_id_list]
            ancestor_stripped = []
            for ancestor in ancestor_id_list:
                ancestor_stripped.append(ancestor.strip())
            record['ancestor_id'] = ancestor_stripped
        if record.get('data_types'):
            data_types_string = record['data_types']
            data_types_list = data_types_string.split(',')
            data_type_stripped = []
            for data_type in data_types_list:
                data_type_stripped.append(data_type.strip())
            record['data_types'] = data_type_stripped
        if record.get('human_gene_sequences'):
            gene_sequences_string = record['human_gene_sequences']
            if gene_sequences_string.lower() == "true":
                record['human_gene_sequences'] = True
            if gene_sequences_string.lower() == "false":
                record['human_gene_sequences'] = False

    validfile = validate_datasets(headers, records, header)
    if validfile == True:
        return Response(json.dumps({'temp_id': temp_id}, sort_keys=True), 201, mimetype='application/json')
    if type(validfile) == list:
        response_body = {"status": "fail", "data": validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400, mimetype='application/json')
    else:
        message = f'Unexpected error occurred while validating tsv file. Expecting validfile to be of type List or Boolean but got type {type(validfile)}'
        response_body = {"status": "fail", "message": message}
        return Response(json.dumps(response_body, sort_keys=True), 500, mimetype='application/json')


@entity_CRUD_blueprint.route('/datasets/bulk', methods=['POST'])
def create_datasets_from_bulk():
    request_data = request.get_json()
    auth_helper_instance = AuthHelper.instance()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    header = {'Authorization': 'Bearer ' + token, 'X-SenNet-Application':'ingest-api' }
    try:
        temp_id = request_data['temp_id']
    except KeyError:
        return_body = {"status": "fail", "message": f"No key 'temp_id' in request body"}
        return Response(json.dumps(return_body, sort_keys=True), 400, mimetype='application/json')
    group_uuid = None
    if "group_uuid" in request_data:
        group_uuid = request_data['group_uuid']
    temp_dir = current_app.config['FILE_UPLOAD_TEMP_DIR']
    tsv_directory = commons_file_helper.ensureTrailingSlash(temp_dir) + temp_id + os.sep
    if not os.path.exists(tsv_directory):
        return_body = {"status": "fail", "message": f"Temporary file with id {temp_id} does not have a temp directory"}
        return Response(json.dumps(return_body, sort_keys=True), 400, mimetype='application/json')
    fcount = 0
    temp_file_name = None
    for tfile in os.listdir(tsv_directory):
        fcount = fcount + 1
        temp_file_name = tfile
    if fcount == 0:
        return Response(json.dumps({"status": "fail", "message": f"File not found in temporary directory /{temp_id}"},
                                   sort_keys=True), 400, mimetype='application/json')
    if fcount > 1:
        return Response(
            json.dumps({"status": "fail", "message": f"Multiple files found in temporary file path /{temp_id}"},
                       sort_keys=True), 400, mimetype='application/json')
    tsvfile_name = tsv_directory + temp_file_name
    records = []
    headers = []
    with open(tsvfile_name, newline='') as tsvfile:
        reader = csv.DictReader(tsvfile, delimiter='\t')
        first = True
        for row in reader:
            data_row = {}
            for key in row.keys():
                if first:
                    headers.append(key)
                data_row[key] = row[key]
            records.append(data_row)
            if first:
                first = False
    # Ancestor_id and data_types can contain multiple entries each. These must be split by comma before validating
    for record in records:
        if record.get('ancestor_id'):
            ancestor_id_string = record['ancestor_id']
            ancestor_id_list = ancestor_id_string.split(',')
            ancestor_stripped = []
            for ancestor in ancestor_id_list:
                ancestor_stripped.append(ancestor.strip())
            record['ancestor_id'] = ancestor_stripped
        if record.get('data_types'):
            data_types_string = record['data_types']
            data_types_list = data_types_string.split(',')
            data_type_stripped = []
            for data_type in data_types_list:
                data_type_stripped.append(data_type.strip())
            record['data_types'] = data_type_stripped
        if record.get('human_gene_sequences'):
            gene_sequences_string = record['human_gene_sequences']
            if gene_sequences_string.lower() == "true":
                record['human_gene_sequences'] = True
            if gene_sequences_string.lower() == "false":
                record['human_gene_sequences'] = False

    validfile = validate_datasets(headers, records, header)

    if type(validfile) == list:
        response_body = {"status": "fail", "data": validfile}
        return Response(json.dumps(response_body, sort_keys=True), 400, mimetype='application/json')
    entity_response = {}
    row_num = 1
    if validfile == True:
        entity_created = False
        entity_failed_to_create = False
        for item in records:
            item['direct_ancestor_uuids'] = item['ancestor_id']
            del item['ancestor_id']
            item['lab_dataset_id'] = item['lab_id']
            del item['lab_id']
            item['description'] = item['doi_abstract']
            del item['doi_abstract']
            item['contains_human_genetic_sequences'] = item['human_gene_sequences']
            del item['human_gene_sequences']
            if group_uuid is not None:
                item['group_uuid'] = group_uuid
            r = requests.post(
                commons_file_helper.ensureTrailingSlashURL(
                    current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/dataset',
                headers=header, json=item)
            entity_response[row_num] = r.json()
            row_num = row_num + 1
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                entity_created = True
        return _send_response_on_file(entity_created, entity_failed_to_create, entity_response)


def _send_response_on_file(entity_created: bool, entity_failed_to_create: bool, entity_response):
    response_status = ''
    if entity_created and not entity_failed_to_create:
        response_status = "Success - All Entities Created Successfully"
        status_code = 201
    elif entity_failed_to_create and not entity_created:
        response_status = "Failure - None of the Entities Created Successfully"
        status_code = 500
    elif entity_created and entity_failed_to_create:
        response_status = "Partial Success - Some Entities Created Successfully"
        status_code = 207
    response = {"status": response_status, "data": entity_response}
    return _send_response(response, status_code)


def _send_response(response, status_code):
    return Response(json.dumps(response, sort_keys=True), status_code, mimetype='application/json')


def _ln_err(error: str, row: int = None, column: str = None):
    return {
        'column': column,
        'error': error,
        'row': row
    }


def _common_ln_errs(err, val):
    if err == 1:
        return _ln_err(f" `{val}` is a required field", 1)
    elif err == 2:
        return _ln_err(f" `{val}` is not an accepted field", 1)
    elif err == 3:
        return _ln_err(f"Unable to validate constraints. Entity Api returned the following: {val}")
    elif err == 4:
        return _ln_err("This row has too few entries. Check file; verify spaces were not used where a tab should be", val)
    elif err == 5:
        return _ln_err("Failed to reach UUID Web Service", val)
    elif err == 6:
        return _ln_err("This row has too many entries. Check file; verify that there are only as many fields as there are headers", val)
    elif err == 7:
        return _ln_err("Unauthorized. Cannot access UUID-api", val)
    elif err == 8:
        return _ln_err("Unable to verify `ancestor_id` exists", val)


def validate_sources(headers, records):
    error_msg = []
    file_is_valid = True
    allowed_source_types = ["human", "human organoid", "mouse", "mouse organoid"]

    required_headers = ['lab_id', 'source_type', 'selection_protocol', 'lab_notes']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(_common_ln_errs(1, field))
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(_common_ln_errs(2, field))
    rownum = 0
    if file_is_valid is True:
        for data_row in records:
            # validate that no fields in data_row are none. If they are none, then we cannot verify even if the entry we
            # are validating is what it is supposed to be. Mark the entire row as bad if a none field exists.
            rownum = rownum + 1
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(_common_ln_errs(4, rownum))
                continue

            # validate that no headers are None. This indicates that there are fields present.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(_common_ln_errs(6, rownum))
                continue

            # validate lab_id
            lab_id = data_row['lab_id']
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(_ln_err("must be fewer than 1024 characters", rownum, "lab_id"))
            if len(lab_id) < 1:
                file_is_valid = False
                error_msg.append(_ln_err("must have 1 or more characters", rownum, "lab_id"))

            # validate selection_protocol
            protocol = data_row['selection_protocol']
            selection_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            selection_protocol_pattern2 = re.match('^[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            if selection_protocol_pattern2 is None and selection_protocol_pattern1 is None:
                file_is_valid = False
                error_msg.append(_ln_err("must either be of the format `https://dx.doi.org/##.####/protocols.io.*` or `##.####/protocols.io.*`", rownum, "selection_protocol"))

            # validate source_type
            if data_row['source_type'].lower() not in allowed_source_types:
                file_is_valid = False
                error_msg.append(_ln_err(f"can only be one of the following (not case sensitive): {', '.join(allowed_source_types)}", rownum, "source_type"))

            # validate description
            description = data_row['lab_notes']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(_ln_err("must be fewer than 10,000 characters", rownum, "lab_notes"))

    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg


def validate_samples(headers, records, header):
    error_msg = []
    file_is_valid = True

    required_headers = ['ancestor_id', 'sample_category', 'preparation_protocol', 'lab_id', 'lab_notes', 'organ_type']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(_common_ln_errs(1, field))
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(_common_ln_errs(2, field))

    allowed_categories = ["block", "section", "suspension", "organ"]

    with urllib.request.urlopen('https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/organ_types.yaml') as urlfile:
        organ_resource_file = yaml.load(urlfile, Loader=yaml.FullLoader)

    rownum = 0
    valid_ancestor_ids = []
    entity_constraint_list = []
    if file_is_valid is True:
        for data_row in records:
            # validate that no fields in data_row are none. If they are none, then we cannot verify even if the entry we
            # are validating is what it is supposed to be. Mark the entire row as bad if a none field exists.
            rownum = rownum + 1
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(_common_ln_errs(4, rownum))
                continue

            # validate that no headers are None. This indicates that there are fields present.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(_common_ln_errs(6, rownum))
                continue

            # validate description
            description = data_row['lab_notes']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(_ln_err("must be fewer than 10,000 characters", rownum, "lab_notes"))

            # validate preparation_protocol
            protocol = data_row['preparation_protocol']
            preparation_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            preparation_protocol_pattern2 = re.match('^[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            if preparation_protocol_pattern2 is None and preparation_protocol_pattern1 is None:
                file_is_valid = False
                error_msg.append(_ln_err("must either be of the format `https://dx.doi.org/##.####/protocols.io.*` or `##.####/protocols.io.*`", rownum, "preparation_protocol"))
            if len(protocol) < 1:
                file_is_valid = False
                error_msg.append(_ln_err("is a required filed and cannot be blank", rownum, "preparation_protocol"))

            # validate lab_id
            lab_id = data_row['lab_id']
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(_ln_err("must be fewer than 1024 characters", rownum, "lab_id"))
            if len(lab_id) < 1:
                file_is_valid = False
                error_msg.append(_ln_err("value cannot be blank", rownum, "lab_id"))

            # validate sample_category
            valid_category = True
            sample_category = data_row['sample_category']
            if sample_category.lower() not in allowed_categories:
                file_is_valid = False
                valid_category = False
                error_msg.append(_ln_err(f"can only be one of the following (not case sensitive): {', '.join(allowed_categories)}", rownum, "sample_category"))

            # validate organ_type
            organ_type = data_row['organ_type']
            if sample_category.lower() != "organ":
                if len(organ_type) > 0:
                    file_is_valid = False
                    error_msg.append(_ln_err("field must be blank if `sample_category` is not `organ`", rownum, "organ_type"))
            if sample_category.lower() == "organ":
                if len(organ_type) < 1:
                    file_is_valid = False
                    error_msg.append(_ln_err("field is required if `sample_category` is `organ`", rownum, "organ_type"))
            if len(organ_type) > 0:
                if organ_type.upper() not in organ_resource_file:
                    file_is_valid = False
                    error_msg.append(_ln_err("value must be an organ code listed in `organ_type` files (https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/organ_types.yaml)", rownum, "organ_type"))

            # validate ancestor_id
            ancestor_id = data_row['ancestor_id']
            validation_results = validate_ancestor_id(header, ancestor_id, error_msg, rownum, valid_ancestor_ids, file_is_valid)

            file_is_valid, error_msg, ancestor_saved, resp_status_code, ancestor_dict \
                = itemgetter('file_is_valid', 'error_msg', 'ancestor_saved', 'resp_status_code', 'ancestor_dict')(validation_results)

            if ancestor_saved or resp_status_code:
                data_row['ancestor_id'] = ancestor_dict['uuid']
                if sample_category.lower() == 'organ' and ancestor_dict['type'].lower() != 'source':
                    file_is_valid = False
                    error_msg.append(_ln_err("If `sample_category` is `organ`, `ancestor_id` must point to a source", rownum))

                if sample_category.lower() != 'organ' and ancestor_dict['type'].lower() != 'sample':
                    file_is_valid = False
                    error_msg.append(_ln_err("If `sample_category` is not `organ`, `ancestor_id` must point to a sample", rownum))

                # prepare entity constraints for validation
                sub_type = None
                sub_type_val = None
                if valid_category:
                    sub_type = get_as_list(sample_category)
                if sample_category.lower() == "organ":
                    sub_type_val = get_as_list(organ_type)

                entity_to_validate = build_constraint_unit('Sample', sub_type, sub_type_val)
                try:
                    entity_constraint_list = append_constraints_list(entity_to_validate, ancestor_dict, header, entity_constraint_list, ancestor_id)

                except Exception as e:
                    file_is_valid = False
                    error_msg.append(_ln_err(f"Unable to access Entity Api during constraint validation. Received response: {e}", rownum))

    # validate entity constraints
    return validate_entity_constraints(file_is_valid, error_msg, header, entity_constraint_list)


def validate_entity_constraints(file_is_valid, error_msg, header, entity_constraint_list):
    url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'constraints?match=true&report_type=ln_err'
    try:
        validate_constraint_result = requests.post(url, headers=header, json=entity_constraint_list)
        if not validate_constraint_result.ok:
            constraint_errors = validate_constraint_result.json()
            error_msg.extend(constraint_errors.get('description'))
            file_is_valid = False
    except Exception as e:
        file_is_valid = False
        error_msg.append(_common_ln_errs(3, e))
    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg


def validate_datasets(headers, records, header):
    error_msg = []
    file_is_valid = True
    assays = []

    required_headers = ['ancestor_id', 'lab_id', 'doi_abstract', 'human_gene_sequences', 'data_types']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(_common_ln_errs(1, field))
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(_common_ln_errs(2, field))

    # retrieve yaml file containing all accepted data types
    with urllib.request.urlopen('https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml') as urlfile:
        assay_resource_file = yaml.load(urlfile, Loader=yaml.FullLoader)

    for each in assay_resource_file:
        assays.append(each.upper())

    rownum = 0
    entity_constraint_list = []
    valid_ancestor_ids = []
    if file_is_valid is True:
        for data_row in records:
            # validate that no fields in data_row are none. If they are none, ,then we cannot verify even if the entry
            # we are validating is what it is supposed to be. Mark the entire row as bad if a none field exists.
            rownum = rownum + 1
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(_common_ln_errs(4, rownum))

                continue

            # validate that no headers are None. This indicates that there are fields present.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(_common_ln_errs(6, rownum))
                continue

            # validate description
            description = data_row['doi_abstract']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(_ln_err("DOI Abstract must be fewer than 10,000 characters", rownum, "doi_abstract"))

            # validate lab_id
            lab_id = data_row['lab_id']
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(_ln_err("must be fewer than 1024 characters", rownum, "lab_id"))

            # validate human_gene_sequences
            has_gene_sequence = data_row['human_gene_sequences']
            if type(has_gene_sequence) is not bool:
                file_is_valid = False
                error_msg.append(_ln_err("must be `true` or `false`", rownum, "has_gene_sequences"))

            # validate data_type
            data_types = data_row['data_types']
            data_types_valid = True
            for data_type in data_types:
                if data_type.upper() not in assays:
                    file_is_valid = False
                    data_types_valid = False
                    error_msg.append(_ln_err("value must be an assay type listed in assay type files (https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml)", rownum, "data_types"))

            if len(data_types) < 1:
                file_is_valid = False
                error_msg.append(_ln_err("must not be empty. Must contain an assay type listed in https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml", rownum, "data_types"))

            # validate ancestor_id
            ancestor_ids = data_row['ancestor_id']
            for ancestor_id in ancestor_ids:
                validation_results = validate_ancestor_id(header, ancestor_id, error_msg, rownum, valid_ancestor_ids, file_is_valid)

                file_is_valid, error_msg, ancestor_saved, resp_status_code, ancestor_dict \
                    = itemgetter('file_is_valid', 'error_msg', 'ancestor_saved', 'resp_status_code', 'ancestor_dict')(validation_results)

                if ancestor_saved or resp_status_code:

                    # prepare entity constraints for validation

                    sub_type = None
                    if data_types_valid:
                        sub_type = get_as_list(data_types)

                    entity_to_validate = build_constraint_unit('Dataset', sub_type)

                    try:
                        entity_constraint_list = append_constraints_list(entity_to_validate, ancestor_dict, header, entity_constraint_list, ancestor_id)
                    except Exception as e:
                        file_is_valid = False
                        error_msg.append(_ln_err(f"Unable to access Entity Api during constraint validation. Received response: {e}", rownum))

    # validate entity constraints
    return validate_entity_constraints(file_is_valid, error_msg, header, entity_constraint_list)


def validate_ancestor_id(header, ancestor_id, error_msg, rownum, valid_ancestor_ids, file_is_valid):
    if len(ancestor_id) < 1:
        file_is_valid = False
        error_msg.append(_ln_err("cannot be blank", rownum, "ancestor_id"))
    if len(ancestor_id) > 0:
        ancestor_dict = {}
        ancestor_saved = False
        resp_status_code = False
        if len(valid_ancestor_ids) > 0:
            for item in valid_ancestor_ids:
                if item.get('uuid') or item.get('sennet_id'):
                    if ancestor_id == item['uuid'] or ancestor_id == item['sennet_id']:
                        ancestor_dict = item
                        ancestor_saved = True
        if ancestor_saved is False:
            url = commons_file_helper.ensureTrailingSlashURL(current_app.config['UUID_WEBSERVICE_URL']) + 'uuid/' + ancestor_id
            try:
                resp = requests.get(url, headers=header)
                if resp.status_code == 404:
                    file_is_valid = False
                    error_msg.append(_common_ln_errs(8, rownum))
                if resp.status_code > 499:
                    file_is_valid = False
                    error_msg.append(_common_ln_errs(5, rownum))
                if resp.status_code == 401 or resp.status_code == 403:
                    file_is_valid = False
                    error_msg.append(_common_ln_errs(7, rownum))
                if resp.status_code == 400:
                    file_is_valid = False
                    error_msg.append(_ln_err(f"`{ancestor_id}` is not a valid id format", rownum))
                if resp.status_code < 300:
                    ancestor_dict = resp.json()
                    valid_ancestor_ids.append(ancestor_dict)
                    resp_status_code = True
            except Exception as e:
                file_is_valid = False
                error_msg.append(_common_ln_errs(5, rownum))

    return {
        'file_is_valid': file_is_valid,
        'error_msg': error_msg,
        'ancestor_dict': ancestor_dict,
        'resp_status_code': resp_status_code,
        'ancestor_saved': ancestor_saved
    }

def append_constraints_list(entity_to_validate, ancestor_dict, header, entity_constraint_list, ancestor_id):

    ancestor_entity_type = ancestor_dict['type'].lower()
    url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + ancestor_id

    ancestor_result = requests.get(url, headers=header).json()
    sub_type = None
    sub_type_val = None
    if ancestor_entity_type == "dataset":
        sub_type = get_as_list(ancestor_result['data_types'])

    if ancestor_entity_type == "sample":
        sub_type = get_as_list(ancestor_result['sample_category'])
        if ancestor_result['sample_category'] == 'organ':
            sub_type_val = get_as_list(ancestor_result['organ'])

    ancestor_to_validate = build_constraint_unit(ancestor_entity_type, sub_type, sub_type_val)

    dict_to_validate = build_constraint(ancestor_to_validate, entity_to_validate)
    entity_constraint_list.append(dict_to_validate)

    return entity_constraint_list


####################################################################################################
## Internal Functions
####################################################################################################


"""
Throws error for 400 Bad Request with message
Parameters
----------
err_msg : str 
    The custom error message to return to end users
"""
def bad_request_error(err_msg):
    abort(400, description = err_msg)