import logging
import os
from flask import Blueprint, make_response, request
import json

from . import ingest_validation_tools_schema_loader as schema_loader
from . import ingest_validation_tools_validation_utils as iv_utils
from . import ingest_validation_tools_table_validator as table_validator
from lib.rest import StatusCodes, get_json_header, server_error, bad_request_error, \
    rest_response, is_json_request, full_response

from lib.file import get_csv_records, get_base_path, check_upload

validation_blueprint = Blueprint('validation', __name__)
logger = logging.getLogger(__name__)


def check_metadata_upload():
    result: dict = {
        'error': None
    }
    file_upload = check_upload('metadata')
    if file_upload.get('code') is StatusCodes.OK:
        file = file_upload.get('description')
        file_id = file.get('id')
        file = file.get('file')
        pathname = file_id + os.sep + file.filename
        result = set_file_details(pathname)
    else:
        result['error'] = file_upload

    return result


def set_file_details(pathname):
    base_path = get_base_path()
    return {
        'pathname': pathname,
        'fullpath': base_path + pathname
    }


def get_metadata(path):
    result = get_csv_records(path)
    return result.get('records')


def validate_tsv(schema='metadata', path=None):
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
    try:
        if is_json_request():
            pathname = request.json.get('pathname')
        else:
            pathname = request.values.get('pathname')

        if pathname is None:
            upload = check_metadata_upload()
        else:
            upload = set_file_details(pathname)

        error = upload.get('error')
        response = error

        if error is None:
            validation_results = validate_tsv(path=upload.get('fullpath'))
            if len(validation_results) > 2:
                response = rest_response(StatusCodes.UNACCEPTABLE, 'Unacceptable Metadata',
                                         json.loads(validation_results))
            else:
                response = rest_response(StatusCodes.OK, None, get_metadata(upload.get('fullpath')))
                response['pathname'] = upload.get('pathname')

    except Exception as e:
        response = server_error(e)

    return full_response(response)
