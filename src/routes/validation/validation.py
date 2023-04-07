import logging
import os
from flask import Blueprint, request, current_app
from hubmap_commons import file_helper as commons_file_helper
import json
import requests
from routes.auth import get_auth_header

from . import ingest_validation_tools_schema_loader as schema_loader
from . import ingest_validation_tools_validation_utils as iv_utils
from . import ingest_validation_tools_table_validator as table_validator
from atlas_consortia_commons.rest import *
from atlas_consortia_commons.string import equals, to_title_case

from lib.file import get_csv_records, get_base_path, check_upload, ln_err
from lib.ontology import Ontology

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
            errors = rest_server_err(e, True)
    return json.dumps(errors)


def get_col_uuid_name_by_entity_type(entity_type):
    if equals(entity_type, Ontology.entities().SAMPLE):
        return 'sample_id'
    else:
        # TODO: This is subject to change when support is raised for Source of Mouse
        return 'uuid'


def get_sub_type_name_by_entity_type(entity_type):
    if equals(entity_type, Ontology.entities().SAMPLE):
        return 'sample_category'
    else:
        # TODO: This is subject to change when support is raised for Source of Mouse
        return 'sub_type'


def validate_records_uuids(records, entity_type, sub_type):
    errors = []
    passing = []
    header = get_auth_header()
    ok = True
    idx = 1
    for r in records:
        uuid_col = get_col_uuid_name_by_entity_type(entity_type)
        uuid = r.get(uuid_col)
        url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + uuid
        resp = requests.get(url, headers=header)
        if resp.status_code < 300:
            entity = resp.json()
            if sub_type is not None:
                sub_type_col = get_sub_type_name_by_entity_type(entity_type)
                _sub_type = entity.get(sub_type_col)
                if not equals(sub_type, _sub_type):
                    ok = False
                    errors.append(rest_response(StatusCodes.UNACCEPTABLE, StatusMsgs.UNACCEPTABLE,
                                                 ln_err(f"got `{to_title_case(_sub_type)}` on check of given `{uuid}`, expected `{sub_type}` for `{sub_type_col}`.",
                                                        idx, uuid_col), dict_only=True))
                else:
                    entity['metadata'] = r
                    passing.append(rest_ok(entity, True))
            else:
                entity['metadata'] = r
                passing.append(rest_ok(entity, True))
        else:
            ok = False
            errors.append(rest_response(resp.status_code, StatusMsgs.UNACCEPTABLE,
                                         ln_err(f"invalid `{uuid_col}` `{uuid}`", idx, uuid_col), dict_only=True))

        idx += 1

    if ok is True:
        return rest_ok(passing, dict_only=True)
    else:
        return rest_response(StatusCodes.UNACCEPTABLE,
                             'There are invalid `uuids` and/or unmatched entity sub types', errors, dict_only=True)


@validation_blueprint.route('/metadata/validate', methods=['POST'])
def validate_metadata_upload():
    try:
        if is_json_request():
            data = request.json
        else:
            data = request.values

        pathname = data.get('pathname')
        entity_type = data.get('entity_type')
        sub_type = data.get('sub_type')
        validate_uuids = data.get('validate_uuids')

        if pathname is None:
            upload = check_metadata_upload()
        else:
            upload = set_file_details(pathname)

        error = upload.get('error')
        response = error

        if error is None:
            if entity_type == Ontology.entities().SOURCE:
                schema = 'donor'
            elif entity_type == Ontology.entities().SAMPLE:
                if not sub_type:
                    return rest_bad_req("`sub_type` for schema name required.")
                schema = f"sample-{sub_type}"
            else:
                schema = 'metadata'
            schema = schema.lower()
            validation_results = validate_tsv(path=upload.get('fullpath'), schema=schema)
            if len(validation_results) > 2:
                response = rest_response(StatusCodes.UNACCEPTABLE, 'Unacceptable Metadata',
                                         json.loads(validation_results), True)
            else:
                records = get_metadata(upload.get('fullpath'))
                if validate_uuids == '1':
                    response = validate_records_uuids(records, entity_type, sub_type)
                else:
                    response = {
                        'code': StatusCodes.OK,
                        'pathname': upload.get('pathname'),
                        'metadata': records
                    }

    except Exception as e:
        response = rest_server_err(e, True)

    return full_response(response)
