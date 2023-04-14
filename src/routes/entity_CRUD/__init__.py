from flask import Blueprint, jsonify, request, Response, current_app, abort, json
import logging
import requests
import os
import re
import urllib.request
import yaml
from hubmap_sdk import EntitySdk
from werkzeug import utils
from operator import itemgetter
from threading import Thread

from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper
from atlas_consortia_commons.rest import *
from atlas_consortia_commons.string import equals
from atlas_consortia_commons.object import includes

from lib.file_upload_helper import UploadFileHelper


entity_CRUD_blueprint = Blueprint('entity_CRUD', __name__)
logger = logging.getLogger(__name__)

# Local modules
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper
from routes.entity_CRUD.dataset_helper import DatasetHelper
from routes.entity_CRUD.constraints_helper import *
from routes.auth import get_auth_header
from lib.ontology import Ontology, enum_val_lower, get_organ_types_ep
from lib.file import get_csv_records, get_base_path, check_upload


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
            abort_bad_req('identifier parameter is required to publish a dataset')
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
    return _bulk_upload_and_validate(Ontology.entities().SOURCE)


@entity_CRUD_blueprint.route('/sources/bulk', methods=['POST'])
def create_sources_from_bulk():
    header = get_auth_header()
    check_results = _check_request_for_bulk()
    group_uuid = check_results.get('group_uuid')
    headers, records = itemgetter('headers', 'records')(check_results.get('csv_records'))
    valid_file = validate_sources(headers, records)

    if type(valid_file) is list:
        return rest_bad_req(valid_file)
    entity_response = {}
    row_num = 1
    if valid_file is True:
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
    return _bulk_upload_and_validate(Ontology.entities().SAMPLE)


@entity_CRUD_blueprint.route('/samples/bulk', methods=['POST'])
def create_samples_from_bulk():
    header = get_auth_header()
    check_results = _check_request_for_bulk()
    group_uuid = check_results.get('group_uuid')
    headers, records = itemgetter('headers', 'records')(check_results.get('csv_records'))

    valid_file = validate_samples(headers, records, header)

    if type(valid_file) is list:
        return rest_bad_req(valid_file)
    entity_response = {}
    row_num = 1
    if valid_file is True:
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
    return _bulk_upload_and_validate(Ontology.entities().DATASET)


@entity_CRUD_blueprint.route('/datasets/bulk', methods=['POST'])
def create_datasets_from_bulk():
    header = get_auth_header()
    check_results = _check_request_for_bulk()
    group_uuid = check_results.get('group_uuid')
    headers, records = itemgetter('headers', 'records')(check_results.get('csv_records'))

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

    valid_file = validate_datasets(headers, records, header)

    if type(valid_file) == list:
        return rest_bad_req(valid_file)
    entity_response = {}
    row_num = 1
    if valid_file is True:
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


@entity_CRUD_blueprint.route('/datasets/<uuid>/submit', methods=['PUT'])
def submit_dataset(uuid):
    if not request.is_json:
        return Response("json request required", 400)
    try:
        dataset_request = request.json
        auth_helper = AuthHelper.configured_instance(current_app.config['APP_CLIENT_ID'],
                                                     current_app.config['APP_CLIENT_SECRET'])
        ingest_helper = IngestFileHelper(current_app.config)
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        dataset_helper = DatasetHelper(current_app.config)
        if isinstance(auth_tokens, Response):
            return (auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        else:
            return (Response("Valid auth token required", 401))

        if 'group_uuid' in dataset_request:
            return Response(
                "Cannot specify group_uuid.  The group ownership cannot be changed after an entity has been created.",
                400)

        group_uuid = dataset_helper.get_group_uuid_by_dataset_uuid(uuid)

        user_info = auth_helper.getUserInfo(token, getGroups=True)
        if isinstance(user_info, Response):
            return user_info
        if not 'hmgroupids' in user_info:
            return Response("user not authorized to submit data, unable to retrieve any group information", 403)
        if not current_app.config['SENNET_DATA_ADMIN_GROUP_UUID'] in user_info['hmgroupids']:
            return Response("user not authorized to submit data, must be a member of the SenNet-Data-Admin group", 403)

        # TODO: Temp fix till we can get this in the "Validation Pipeline"... add the validation code here... If it returns any errors fail out of this. Return 412 Precondition Failed with the errors in the description.
        pipeline_url = commons_file_helper.ensureTrailingSlashURL(
            current_app.config['INGEST_PIPELINE_URL']) + 'request_ingest'
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)
    try:
        put_url = commons_file_helper.ensureTrailingSlashURL(
            current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + uuid
        dataset_request['status'] = 'Processing'
        response = requests.put(put_url, json=dataset_request,
                                headers={'Authorization': 'Bearer ' + token, 'X-SenNet-Application': 'ingest-api'},
                                verify=False)
        if not response.status_code == 200:
            error_msg = f"call to {put_url} failed with code:{response.status_code} message:" + response.text
            logger.error(error_msg)
            return Response(error_msg, response.status_code)
    except HTTPException as hte:
        logger.error(hte)
        return Response("Unexpected error while updating dataset: " + str(e) + "  Check the logs", 500)

    def call_airflow():
        try:
            request_ingest_payload = {
                "submission_id": "{uuid}".format(uuid=uuid),
                "process": "SCAN.AND.BEGIN.PROCESSING",
                "full_path": ingest_helper.get_dataset_directory_absolute_path(dataset_request, group_uuid, uuid),
                "provider": "{group_name}".format(group_name=AuthHelper.getGroupDisplayName(group_uuid))
            }
            logger.info('Request_ingest_payload : ' + json.dumps(request_ingest_payload, indent=4, default=str))
            r = requests.post(pipeline_url, json=request_ingest_payload,
                              headers={'Content-Type': 'application/json', 'Authorization': 'Bearer {token}'.format(
                                  token=AuthHelper.instance().getProcessSecret())}, verify=False)
            if r.ok == True:
                """expect data like this:
                {"ingest_id": "abc123", "run_id": "run_657-xyz", "overall_file_count": "99", "top_folder_contents": "["IMS", "processed_microscopy","raw_microscopy","VAN0001-RK-1-spatial_meta.txt"]"}
                """
                data = json.loads(r.content.decode())
                submission_data = data['response']
                dataset_request['ingest_id'] = submission_data['ingest_id']
                dataset_request['run_id'] = submission_data['run_id']
            else:
                error_message = 'Failed call to AirFlow HTTP Response: ' + str(r.status_code) + ' msg: ' + str(r.text)
                logger.error(error_message)
                dataset_request['status'] = 'Error'
                dataset_request['pipeline_message'] = error_message
            response = requests.put(put_url, json=dataset_request,
                                    headers={'Authorization': 'Bearer ' + token, 'X-SenNet-Application': 'ingest-api'},
                                    verify=False)
            if not response.status_code == 200:
                error_msg = f"call to {put_url} failed with code:{response.status_code} message:" + response.text
                logger.error(error_msg)
            else:
                logger.info(response.json())
        except HTTPException as hte:
            logger.error(hte)
        except Exception as e:
            logger.error(e, exc_info=True)

    thread = Thread(target=call_airflow)
    thread.start()
    return Response("Request of Dataset Submisssion Accepted", 202)


@entity_CRUD_blueprint.route('/datasets/status', methods=['PUT'])
# @secured(groups="HuBMAP-read")
def update_ingest_status():
    if not request.json:
        abort_bad_req('no data found cannot process update')

    try:
        auth_helper_instance = AuthHelper.instance()
        file_upload_helper_instance = UploadFileHelper.instance()
        entity_api = EntitySdk(token=auth_helper_instance.getAuthorizationTokens(request.headers),
                               service_url=commons_file_helper.removeTrailingSlashURL(
                                   current_app.config['ENTITY_WEBSERVICE_URL']))
        dataset_helper = DatasetHelper(current_app.config)

        return dataset_helper.update_ingest_status_title_thumbnail(current_app.config,
                                                                request.json,
                                                                request.headers,
                                                                entity_api,
                                                                file_upload_helper_instance)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except ValueError as ve:
        logger.error(str(ve))
        abort_bad_req(ve)
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while saving dataset: " + str(e), 500)


def _bulk_upload_and_validate(entity):
    header = get_auth_header()
    upload = check_upload()
    temp_id, file = itemgetter('id', 'file')(upload.get('description'))
    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    file.filename = utils.secure_filename(file.filename)
    file_location = get_base_path() + temp_id + os.sep + file.filename
    csv_records = get_csv_records(file_location)
    headers, records = itemgetter('headers', 'records')(csv_records)

    if entity == Ontology.entities().SOURCE:
        valid_file = validate_sources(headers, records)
    elif entity == Ontology.entities().SAMPLE:
        valid_file = validate_samples(headers, records, header)
    elif entity == Ontology.entities().DATASET:
        records = _format_dataset_records(records)
        valid_file = validate_datasets(headers, records, header)
    else:
        valid_file = False

    if valid_file is True:
        return rest_ok({'temp_id': temp_id})
    elif type(valid_file) is list:
        return rest_bad_req(valid_file)
    else:
        message = f'Unexpected error occurred while validating tsv file. Expecting valid_file to be of type List or Boolean but got type {type(valid_file)}'
        return rest_server_err(message)


def _format_dataset_records(records):
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

    return records


def _check_request_for_bulk():
    request_data = request.get_json()
    try:
        temp_id = request_data['temp_id']
    except KeyError:
        return rest_bad_req('No key `temp_id` in request body')
    group_uuid = None
    if "group_uuid" in request_data:
        group_uuid = request_data['group_uuid']
    temp_dir = current_app.config['FILE_UPLOAD_TEMP_DIR']
    tsv_directory = commons_file_helper.ensureTrailingSlash(temp_dir) + temp_id + os.sep
    if not os.path.exists(tsv_directory):
        return rest_bad_req(f"Temporary file with id {temp_id} does not have a temp directory")
    fcount = 0
    temp_file_name = None
    for tfile in os.listdir(tsv_directory):
        fcount = fcount + 1
        temp_file_name = tfile
    if fcount == 0:
        return rest_bad_req(f"File not found in temporary directory /{temp_id}")
    if fcount > 1:
        return rest_bad_req(f"Multiple files found in temporary file path /{temp_id}")
    file_location = tsv_directory + temp_file_name
    return {
        'csv_records': get_csv_records(file_location),
        'group_uuid': group_uuid
    }


def _send_response_on_file(entity_created: bool, entity_failed_to_create: bool, entity_response):
    if entity_created and not entity_failed_to_create:
        return rest_ok(entity_response)
    elif entity_created and entity_failed_to_create:
        return rest_response(StatusCodes.OK_PARTIAL, "Partial Success - Some Entities Created Successfully", entity_response)
    else:
        return rest_server_err(f"entity_created: {entity_created}, entity_failed_to_create: {entity_failed_to_create}")


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
    allowed_source_types = Ontology.source_types(True, enum_val_lower)

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

    allowed_categories = Ontology.specimen_categories(True, enum_val_lower)
    # Get the ontology classes
    SpecimenCategories = Ontology.specimen_categories()
    Entities = Ontology.entities()

    organ_types_codes = list(Ontology.organ_types(as_data_dict=True).keys())

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
            data_row['organ_type'] = data_row['organ_type'].upper()
            organ_type = data_row['organ_type']
            if not equals(sample_category, SpecimenCategories.ORGAN):
                if len(organ_type) > 0:
                    file_is_valid = False
                    error_msg.append(_ln_err("field must be blank if `sample_category` is not `organ`", rownum, "organ_type"))
            if equals(sample_category, SpecimenCategories.ORGAN):
                if len(organ_type) < 1:
                    file_is_valid = False
                    error_msg.append(_ln_err("field is required if `sample_category` is `organ`", rownum, "organ_type"))
            if len(organ_type) > 0:
                if organ_type not in organ_types_codes:
                    file_is_valid = False
                    error_msg.append(_ln_err(f"value must be an organ code listed in `organ_type` files {get_organ_types_ep()}", rownum, "organ_type"))

            # validate ancestor_id
            ancestor_id = data_row['ancestor_id']
            validation_results = validate_ancestor_id(header, ancestor_id, error_msg, rownum, valid_ancestor_ids, file_is_valid)

            file_is_valid, error_msg, ancestor_saved, resp_status_code, ancestor_dict \
                = itemgetter('file_is_valid', 'error_msg', 'ancestor_saved', 'resp_status_code', 'ancestor_dict')(validation_results)

            if ancestor_saved or resp_status_code:
                data_row['ancestor_id'] = ancestor_dict['uuid']
                if equals(sample_category, SpecimenCategories.ORGAN) and not equals(ancestor_dict['type'], Entities.SOURCE):
                    file_is_valid = False
                    error_msg.append(_ln_err("If `sample_category` is `organ`, `ancestor_id` must point to a source", rownum))

                if not equals(sample_category, SpecimenCategories.ORGAN) and not equals(ancestor_dict['type'], Entities.SAMPLE):
                    file_is_valid = False
                    error_msg.append(_ln_err("If `sample_category` is not `organ`, `ancestor_id` must point to a sample", rownum))

                # prepare entity constraints for validation
                sub_type = None
                sub_type_val = None
                if valid_category:
                    sub_type = get_as_list(sample_category)
                if equals(sample_category, SpecimenCategories.ORGAN):
                    sub_type_val = get_as_list(organ_type)

                entity_to_validate = build_constraint_unit(Entities.SAMPLE, sub_type, sub_type_val)
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

    assay_types = list(Ontology.assay_types(as_data_dict=True, prop_callback=None).keys())

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
            for i, data_type in enumerate(data_types):
                idx = includes(assay_types, data_type, single_index=True)

                if idx == -1:
                    file_is_valid = False
                    data_types_valid = False
                    error_msg.append(_ln_err("value must be an assay type listed in assay type files (https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml)", rownum, "data_types"))
                else:
                    # apply formatting
                    data_types[i] = assay_types[idx]

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

                    entity_to_validate = build_constraint_unit(Ontology.entities().DATASET, sub_type)

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
    Entities = Ontology.entities()
    ancestor_entity_type = ancestor_dict['type'].lower()
    url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + ancestor_id

    ancestor_result = requests.get(url, headers=header).json()
    sub_type = None
    sub_type_val = None
    if equals(ancestor_entity_type, Entities.DATASET):
        sub_type = get_as_list(ancestor_result['data_types'])

    if equals(ancestor_entity_type, Entities.SAMPLE):
        sub_type = get_as_list(ancestor_result['sample_category'])
        if equals(ancestor_result['sample_category'], Ontology.specimen_categories().ORGAN):
            sub_type_val = get_as_list(ancestor_result['organ'])

    ancestor_to_validate = build_constraint_unit(ancestor_entity_type, sub_type, sub_type_val)

    dict_to_validate = build_constraint(ancestor_to_validate, entity_to_validate)
    entity_constraint_list.append(dict_to_validate)

    return entity_constraint_list