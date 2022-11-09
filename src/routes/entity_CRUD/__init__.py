from flask import Blueprint, jsonify, request, Response, current_app, abort, json
import logging
import requests
import os
import csv
import re
import urllib.request
import yaml
from werkzeug import utils

from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper

entity_CRUD_blueprint = Blueprint('entity_CRUD', __name__)
logger = logging.getLogger(__name__)

# Local modules
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper
from routes.entity_CRUD.file_upload_helper import UploadFileHelper

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
        return_validfile = {}
        error_num = 0
        for item in validfile:
            return_validfile[str(error_num)] = str(item)
            error_num = error_num + 1
        response_body = {"status": "fail", "data": return_validfile}
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
    temp_id = request_data['temp_id']
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
        return Response(json.dumps(response, sort_keys=True), status_code, mimetype='application/json')


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
        return_validfile = {}
        error_num = 0
        for item in validfile:
            return_validfile[str(error_num)] = str(item)
            error_num = error_num + 1
        response_body = {"status": "fail", "data": return_validfile}
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
    temp_id = request_data['temp_id']
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
            item['direct_ancestor_uuid'] = item['ancestor_id']
            del item['ancestor_id']
            item['lab_tissue_sample_id'] = item['lab_id']
            del item['lab_id']
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
        return Response(json.dumps(response, sort_keys=True), status_code, mimetype='application/json')


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
        return_validfile = {}
        error_num = 0
        for item in validfile:
            return_validfile[str(error_num)] = str(item)
            error_num = error_num + 1
        response_body = {"status": "fail", "data": return_validfile}
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
    temp_id = request_data['temp_id']
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
            item['direct_ancestor_uuids'] = item['ancestor_id']
            del item['ancestor_id']
            item['lab_dataset_id'] = item['lab_id']
            del item['lab_id']
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
        return Response(json.dumps(response, sort_keys=True), status_code, mimetype='application/json')


def validate_sources(headers, records):
    error_msg = []
    file_is_valid = True
    allowed_source_types = ["human", "human organoid", "mouse", "mouse organoid"]

    required_headers = ['lab_id', 'source_type', 'selection_protocol', 'description']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(f"{field} is a required field")
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(f"{field} is not an accepted field")
    rownum = 1
    if file_is_valid is True:
        for data_row in records:
            # validate that no fields in data_row are none. If they are none, then we cannot verify even if the entry we
            # are validating is what it is supposed to be. Mark the entire row as bad if a none field exists.
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. This row has too few entries. Check file; verify spaces were not used where a tab should be")
                continue

            # validate that no headers are None. This indicates that there are fields present.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. This row has too many entries. Check file; verify that there are only as many fields as there are headers")
                continue

            # validate lab_id
            lab_id = data_row['lab_id']
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id must be fewer than 1024 characters")
            if len(lab_id) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id must have 1 or more characters")

            # validate selection_protocol
            protocol = data_row['selection_protocol']
            selection_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            selection_protocol_pattern2 = re.match('^[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            if selection_protocol_pattern2 is None and selection_protocol_pattern1 is None:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. selection_protocol must either be of the format https://dx.doi.org/##.####/protocols.io.* or ##.####/protocols.io.*")

            # validate source_type
            if data_row['source_type'].lower() not in allowed_source_types:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. source_type can only be one of the following (not case sensitive): {', '.join(allowed_source_types)}"
                )

            # validate description
            description = data_row['description']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. Description must be fewer than 10,000 characters")

            rownum = rownum + 1

    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg

def validate_samples(headers, records, header):
    error_msg = []
    file_is_valid = True

    required_headers = ['ancestor_id', 'sample_category', 'preparation_protocol', 'lab_id', 'description', 'organ_type']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(f"{field} is a required field")
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(f"{field} is not an accepted field")

    allowed_categories = ["block", "section", "suspension", "bodily fluid", "organ", "organ piece"]

    with urllib.request.urlopen('https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/organ_types.yaml') as urlfile:
        organ_resource_file = yaml.load(urlfile, Loader=yaml.FullLoader)

    rownum = 1
    valid_ancestor_ids = []
    if file_is_valid is True:
        for data_row in records:
            # validate that no fields in data_row are none. If they are none, then we cannot verify even if the entry we
            # are validating is what it is supposed to be. Mark the entire row as bad if a none field exists.
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. This row has too few entries. Check file; verify spaces were not used where a tab should be")
                continue

            # validate that no headers are None. This indicates that there are fields present.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. This row has too many entries. Check file; verify that there are only as many fields as there are headers")
                continue

            # validate description
            description = data_row['description']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. Description must be fewer than 10,000 characters")

            # validate preparation_protocol
            protocol = data_row['preparation_protocol']
            preparation_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            preparation_protocol_pattern2 = re.match('^[\d]+\.[\d]+/protocols\.io\.[\w]*$', protocol)
            if preparation_protocol_pattern2 is None and preparation_protocol_pattern1 is None:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. preparation_protocol must either be of the format https://dx.doi.org/##.####/protocols.io.* or ##.####/protocols.io.*")
            if len(protocol) < 1:
                file_is_valid = False
                error_msg.append(f"row Number: {rownum}. preparation_protocol is a required filed and cannot be blank.")

            # validate lab_id
            lab_id = data_row['lab_id']
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id must be fewer than 1024 characters")
            if len(lab_id) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id value cannot be blank")

            # validate sample_category
            sample_category = data_row['sample_category']
            if sample_category.lower() not in allowed_categories:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. sample_category can only be one of the following (not case sensitive): {', '.join(allowed_categories)}"
                )

            # validate organ_type
            organ_type = data_row['organ_type']
            if sample_category.lower() != "organ":
                if len(organ_type) > 0:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. organ_type field must be blank if sample_category is not 'organ'")
            if sample_category.lower() == "organ":
                if len(organ_type) < 1:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. organ_type field is required if sample_category is 'organ'")
            if len(organ_type) > 0:
                if organ_type.upper() not in organ_resource_file:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. organ_type value must be an organ code listed in organ type files (https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/organ_types.yaml)")

            # validate ancestor_id
            ancestor_id = data_row['ancestor_id']
            if len(ancestor_id) < 1:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. ancestor_id cannot be blank")
            if len(ancestor_id) > 0:
                ancestor_dict = {}
                ancestor_saved = False
                resp_status_code = False
                if len(valid_ancestor_ids) > 0:
                    for item in valid_ancestor_ids:
                        if item['uuid'] or item['sennet_id']:
                            if ancestor_id == item['uuid'] or ancestor_id == item['sennet_id']:
                                ancestor_dict = item
                                ancestor_saved = True
                if ancestor_saved is False:
                    url = commons_file_helper.ensureTrailingSlashURL(current_app.config['UUID_WEBSERVICE_URL']) + 'uuid/' + ancestor_id
                    try:
                        resp = requests.get(url, headers=header)
                        if resp.status_code == 404:
                            file_is_valid = False
                            error_msg.append(f"Row Number: {rownum}. Unable to verify ancestor_id exists")
                        if resp.status_code > 499:
                            file_is_valid = False
                            error_msg.append(f"Row Number: {rownum}. Failed to reach UUID Web Service")
                        if resp.status_code == 401:
                            file_is_valid = False
                            error_msg.append(f"Row Number: {rownum}. Unauthorized. Cannot access UUID-api")
                        if resp.status_code == 400:
                            file_is_valid = False
                            error_msg.append(f"Row Number: {rownum}. {ancestor_id} is not a valid id format")
                        if resp.status_code < 300:
                            ancestor_dict = resp.json()
                            valid_ancestor_ids.append(ancestor_dict)
                            resp_status_code = True
                    except Exception as e:
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. Failled to reach UUID Web Service")
                if ancestor_saved or resp_status_code:
                    data_row['ancestor_id'] = ancestor_dict['uuid']
                    if sample_category.lower() == 'organ' and ancestor_dict['type'].lower() != 'source':
                        file_is_valid = False
                        error_msg.append(
                            f"Row Number: {rownum}. If sample category is organ, ancestor_id must point to a source")
                    if sample_category.lower() != 'organ' and ancestor_dict['type'].lower() != 'sample':
                        file_is_valid = False
                        error_msg.append(
                            f"Row Number: {rownum}. If sample category is not organ, ancestor_id must point to a sample")


            rownum = rownum + 1

    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg

def validate_datasets(headers, records, header):
    error_msg = []
    file_is_valid = True

    required_headers = ['ancestor_id', 'lab_id', 'description', 'human_gene_sequences', 'data_types']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(f"{field} is a required field")
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(f"{field} is not an accepted field")

    # retrieve yaml file containing all accepted data types
    with urllib.request.urlopen('https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml') as urlfile:
        assay_resource_file = yaml.load(urlfile, Loader=yaml.FullLoader)

    for each in assay_resource_file:
        assay_resource_file[each] = each.upper()

    rownum = 1
    valid_ancestor_ids = []
    if file_is_valid is True:
        for data_row in records:
            # validate that no fields in data_row are none. If they are none, ,then we cannot verify even if the entry
            # we are validating is what it is supposed to be. Mark the entire row as bad if a none field exists.
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. This row has too few entries. Check file; verify spaces were not used where a tab should be")
                continue

            # validate that no headers are None. This indicates taht there are fields present.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(
                    f"Row Number: {rownum}. This row has too many entries. Check file; verify that there are are only as many fields as there are headers")
                continue

            # validate description
            description = data_row['description']
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. Description must be fewer than 10,000 characters")

            # validate ancestor_id
            ancestor_id = data_row['ancestor_id']
            for ancestor in ancestor_id:
                ancestor_saved = False
                if len(valid_ancestor_ids) > 0:
                    for item in valid_ancestor_ids:
                        if item['uuid'] or item['sennet_id']:
                            if ancestor == item['uuid'] or ancestor == item['sennet_id']:
                                ancestor_saved = True
                if ancestor_saved is False:
                    url = commons_file_helper.ensureTrailingSlashURL(current_app.config['UUID_WEBSERVICE_URL']) + 'uuid/' + ancestor
                    try:
                        resp = requests.get(url, headers=header)
                        if resp.status_code == 404:
                            file_is_valid = False
                            error_msg.append(f"Row Number: {rownum}. Unable to verify ancestor_id exists")
                        if resp.status_code > 499:
                            file_is_valid = False
                            #error_msg.append(f"Row Number: {rownum}. Failed to reach UUID Web Service")
                            error_msg.append(resp.request.url)
                        if resp.status_code == 401 or resp.status_code == 403:
                            file_is_valid = False
                            error_msg.append(f"Row Number: {rownum}. Unauthorized. Cannot access UUID-api")
                        if resp.status_code == 400:
                            file_is_valid = False
                            error_msg.append(f"Row Number: {rownum}. {ancestor} is not a valid id format")
                        if resp.status_code < 300:
                            ancestor_dict = resp.json()
                            valid_ancestor_ids.append(ancestor_dict)
                    except Exception as e:
                        file_is_valid = False
                        error_msg.append(f"Row Number: {rownum}. Failed to reach UUID Web Service")

            # validate lab_id
            lab_id = data_row['lab_id']
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. lab_id must be fewer than 1024 characters")

            # validate human_gene_sequences
            has_gene_sequence = data_row['human_gene_sequences']
            if type(has_gene_sequence) is not bool:
                file_is_valid = False
                error_msg.append(f"Row Number: {rownum}. has_gene_sequences must be 'true' or 'false'")

            # validate data_type
            data_types = data_row['data_types']
            for data_type in data_types:
                if data_type.upper() not in assay_resource_file:
                    file_is_valid = False
                    error_msg.append(f"Row Number: {rownum}. data_type value must be an assay type listed in assay type files (https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml)")

            rownum = rownum + 1

    if file_is_valid:
        return file_is_valid
    if file_is_valid == False:
        return error_msg


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