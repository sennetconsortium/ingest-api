import logging
import os
from flask import Blueprint, make_response, request, abort, current_app
from hubmap_commons import file_helper as commons_file_helper
from werkzeug import utils
import csv
import json

from routes.entity_CRUD.file_upload_helper import UploadFileHelper

# from . import ingest_validation_tools_error_report as error_report
# from . import ingest_validation_tools_upload as upload
from . import ingest_validation_tools_schema_loader as schema_loader
from . import ingest_validation_tools_validation_utils as iv_utils
from . import ingest_validation_tools_table_validator as table_validator

validation_blueprint = Blueprint('validation', __name__)
logger = logging.getLogger(__name__)


def bad_request_error(err_msg):
    abort(400, description=err_msg)


def check_upload():
    file = None
    result: dict = {
        'error': None
    }
    try:
        if not UploadFileHelper.is_initialized():
            file_upload_helper_instance = UploadFileHelper.create(current_app.config['FILE_UPLOAD_TEMP_DIR'],
                                                                  current_app.config['FILE_UPLOAD_DIR'],
                                                                  current_app.config['UUID_WEBSERVICE_URL'])
            logger.info("Initialized UploadFileHelper class successfully :)")
        else:
            file_upload_helper_instance = UploadFileHelper.instance()

        key = 'metadata'
        if key not in request.files:
            bad_request_error('No file part')
        file = request.files[key]
        if file.filename == '':
            bad_request_error('No selected file')

        file.filename = file.filename.replace(" ", "_")
        temp_id = file_upload_helper_instance.save_temp_file(file)
        file.filename = utils.secure_filename(file.filename)
        base_path = commons_file_helper.ensureTrailingSlash(current_app.config['FILE_UPLOAD_TEMP_DIR'])
        result['location'] = base_path + temp_id + os.sep + file.filename
        result['file'] = file
    except Exception as e:
        print(e)
        if hasattr(e, 'code'):
            result['error'] = {
                'code': e.code,
                'name': e.name,
                'description': e.description
            }
        else:
            result['error'] = server_error(e)

    return result

def get_metadata(upload):
    records = []
    headers = []
    with open(upload['location'], newline='') as tsvfile:
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

    return records

def server_error(e):
    return {
        'code': 500,
        'name': 'Server Error',
        'description': f"{e}"
    }

def validate_tsvs(schema='metadata', path=None):
    try:
        schema_name = (
            schema if schema != 'metadata'
            else iv_utils.get_table_schema_version(path, 'ascii').schema_name
        )
    except schema_loader.PreflightError as e:
        errors = {'Preflight': str(e)}
    else:
        try:
            errors = iv_utils.get_tsv_errors(path, schema_name=schema_name, report_type=table_validator.ReportType.JSON)
        except Exception as e:
            errors = server_error(e)
    return json.dumps(errors)


@validation_blueprint.route('/validation', methods=['POST'])
def validate_metadata_upload():

    upload = check_upload()
    error = upload['error']
    response = error
    entity = request.values['entity']
    if error is None:
        validation_results = validate_tsvs(path=upload['location'])
        if len(validation_results) > 2:
            response = {
                'code': 406,
                'name': 'Unacceptable Metadata',
                'description': json.loads(validation_results)
            }
        else:
            response = {
                'code': 200,
                'metadata': get_metadata(upload)
            }

    headers: dict = {
        "Content-Type": "application/json"
    }
    return make_response(response, response['code'], headers)