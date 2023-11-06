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
import time
import csv

from ..privs import get_groups_token

validation_blueprint = Blueprint('validation', __name__)
logger = logging.getLogger(__name__)


"""
Checks the uploaded file

Returns
-------
dict
    A dictionary of containing upload details or an 'error' key if something went wrong
"""
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


"""
Creates a dictionary of file and path details

Returns
-------
dict
    A dictionary containing the filename and fullpath details
"""
def set_file_details(pathname):
    base_path = get_base_path()
    return {
        'pathname': pathname,
        'fullpath': base_path + pathname
    }


"""
Parses a tsv and returns the rows of that tsv

Parameters
----------
path : str
    The path where the tsv file is stored
    
Returns
-------
list
    A list of dictionaries
"""
def get_metadata(path):
    result = get_csv_records(path)
    return result.get('records')


"""
Calls methods of the Ingest Validation Tools submodule

Parameters
----------
schema : str
    Name of the schema to validate against
path : str
    The path of the tsv for Ingest Validation Tools
    
Returns
-------
dict
    A dictionary containing validation results
"""
def validate_tsv(schema='metadata', path=None):
    try:
        schema_name = (
            schema if schema != 'metadata'
            else iv_utils.get_table_schema_version(path, 'ascii').schema_name
        )
    except schema_loader.PreflightError as e:
        result = {'Preflight': str(e)}
    else:
        try:
            app_context = {
                'request_header': {'X-SenNet-Application': 'ingest-api'},
                'entities_url': f"{commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL'])}entities/"
            }
            result = iv_utils.get_tsv_errors(path, schema_name=schema_name, report_type=table_validator.ReportType.JSON,
                                             cedar_api_key=current_app.config['CEDAR_API_KEY'], globus_token=get_groups_token(), app_context=app_context)
        except Exception as e:
            result = rest_server_err(e, True)
    return json.dumps(result)


"""
Creates a tsv from path of a specific row.
This is in order to validate only one if necessary.

Parameters
----------
path : str
    Path of original tsv
row : int
    Row number in tsv to extract for new tsv
    
Returns
-------
dict
    A dictionary containing file details
"""
def create_tsv_from_path(path, row):

    result: dict = {
        'error': None
    }
    try:
        records = get_csv_records(path, records_as_arr=True)
        result = set_file_details(f"{time.time()}.tsv")

        with open(result.get('fullpath'), 'wt') as out_file:
            tsv_writer = csv.writer(out_file, delimiter='\t')
            tsv_writer.writerow(records.get('headers'))
            tsv_writer.writerow(records.get('records')[row])
    except Exception as e:
        result = rest_server_err(e, True)

    return result

def get_cedar_schema_ids():
    return {
        'Block': '3e98cee6-d3fb-467b-8d4e-9ba7ee49eeff',
        'Section': '01e9bc58-bdf2-49f4-9cf9-dd34f3cc62d7',
        'Suspension': 'ea4fb93c-508e-4ec4-8a4b-89492ba68088'
    }


def check_cedar(entity_type, sub_type, upload):
    records = get_metadata(upload.get('fullpath'))
    if len(records) > 0:
        if equals(entity_type, Ontology.ops().entities().SAMPLE) and 'metadata_schema_id' in records[0]:
            cedar_sample_sub_type_ids = get_cedar_schema_ids()
            return equals(records[0]['metadata_schema_id'], cedar_sample_sub_type_ids[sub_type])
    return True

def determine_schema(entity_type, sub_type):
    if equals(entity_type, Ontology.ops().entities().SOURCE):
        schema = 'murine-source'
    elif equals(entity_type, Ontology.ops().entities().SAMPLE):
        if not sub_type:
            return rest_bad_req("`sub_type` for schema name required.")
        schema = f"sample-{sub_type}"
    else:
        schema = 'metadata'

    schema = schema.lower()
    return schema


def _get_response(metadata, entity_type, sub_type, validate_uuids, pathname=None):
    if validate_uuids == '1':
        response = validate_records_uuids(metadata, entity_type, sub_type, pathname)
    else:
        response = {
            'code': StatusCodes.OK,
            'pathname': pathname,
            'metadata': metadata
        }

    return response

"""
Returns the tsv id column name for the given entity type

Parameters
----------
entity_type : str
    The entity type
    
Returns
-------
str
    The name of the column in the tsv
"""
def get_col_id_name_by_entity_type(entity_type):
    if equals(entity_type, Ontology.ops().entities().SAMPLE):
        return 'sample_id'
    else:
        return 'source_id'


def get_sub_type_name_by_entity_type(entity_type):
    if equals(entity_type, Ontology.ops().entities().SAMPLE):
        return 'sample_category'
    else:
        return 'source_type'


def supported_metadata_sub_types(entity_type):
    if equals(entity_type, Ontology.ops().entities().SOURCE):
        return [Ontology.ops().source_types().MOUSE]
    else:
        return [
            Ontology.ops().specimen_categories().BLOCK,
            Ontology.ops().specimen_categories().SECTION,
            Ontology.ops().specimen_categories().SUSPENSION]

"""
Validates the uuids / SenNet ids of given records.
This is used for bulk upload so that ancestor ids referenced by the user in TSVs
are found to actually exist, are supported and confirm to entity constraints.

Parameters
----------
records : list
    The set of records to validate
entity_type : str
    The entity type
sub_type : str
    The sub type of the entity
pathname : str
    The pathname of the tsv. 
    (This is always returned in the response for tracking and other re-validation purposes.)
    
Returns
-------
Response
    Rest response containing results of validation
"""
def validate_records_uuids(records, entity_type, sub_type, pathname):
    errors = []
    passing = []
    header = get_auth_header()
    ok = True
    idx = 1
    for r in records:
        # First get the id column name, in order to get SenNet id in the record
        id_col = get_col_id_name_by_entity_type(entity_type)
        entity_id = r.get(id_col)
        # Use the SenNet id to find the stored entity
        url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + entity_id
        resp = requests.get(url, headers=header)
        if resp.status_code < 300:
            entity = resp.json()
            if sub_type is not None:
                sub_type_col = get_sub_type_name_by_entity_type(entity_type)
                _sub_type = entity.get(sub_type_col)
                # Check that the stored entity _sub_type is actually supported for validation
                if _sub_type not in supported_metadata_sub_types(entity_type):
                    ok = False
                    errors.append(rest_response(StatusCodes.UNACCEPTABLE, StatusMsgs.UNACCEPTABLE,
                                                ln_err(f"of `{to_title_case(_sub_type)}` unsupported "
                                                       f"on check of given `{entity_id}`. "
                                                       f"Supported `{'`, `'.join(supported_metadata_sub_types(entity_type))}`.",
                                                       idx, sub_type_col), dict_only=True))
                # Check that the stored entity _sub_type matches what is expected (the type being bulk uploaded)
                elif not equals(sub_type, _sub_type):
                    ok = False
                    errors.append(rest_response(StatusCodes.UNACCEPTABLE, StatusMsgs.UNACCEPTABLE,
                                                 ln_err(f"got `{to_title_case(_sub_type)}` on check of given `{entity_id}`, "
                                                        f"expected `{sub_type}` for `{sub_type_col}`.",
                                                        idx, id_col), dict_only=True))
                else:
                    entity['metadata'] = r
                    passing.append(rest_ok(entity, True))
            else:
                entity['metadata'] = r
                passing.append(rest_ok(entity, True))
        else:
            ok = False
            errors.append(rest_response(resp.status_code, StatusMsgs.UNACCEPTABLE,
                                         ln_err(f"invalid `{id_col}`: '{entity_id}'", idx, id_col), dict_only=True))

        idx += 1

    if ok is True:
        return rest_ok({'data': passing, 'pathname': pathname}, dict_only=True)
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
        tsv_row = data.get('tsv_row')

        if pathname is None:
            upload = check_metadata_upload()
        else:
            if tsv_row is None:
                upload = set_file_details(pathname)
            else:
                upload = create_tsv_from_path(get_base_path() + pathname, int(tsv_row))

        error = upload.get('error')
        response = error

        if error is None:
            if check_cedar(entity_type, sub_type, upload) is False:
                id = get_cedar_schema_ids().get(sub_type)
                return rest_response(StatusCodes.UNACCEPTABLE, 'Unacceptable Metadata',
                                     f"Mismatch of \"{entity_type} {sub_type}\" and \"metadata_schema_id\". Valid id for \"{sub_type}\": {id}. "
                                     f"For more details, check out the docs: https://docs.sennetconsortium.org/libraries/ingest-validation-tools/schemas")

            schema = determine_schema(entity_type, sub_type)
            validation_results = validate_tsv(path=upload.get('fullpath'), schema=schema)
            if len(validation_results) > 2:
                response = rest_response(StatusCodes.UNACCEPTABLE, 'Unacceptable Metadata',
                                         json.loads(validation_results), True)
            else:
                records = get_metadata(upload.get('fullpath'))
                response = _get_response(records, entity_type, sub_type, validate_uuids, pathname=upload.get('pathname'))
                if tsv_row is not None:
                    os.remove(upload.get('fullpath'))

    except Exception as e:
        response = rest_server_err(e, True)

    return full_response(response)
