from flask import Blueprint, jsonify, request, Response, current_app, json
import logging
import requests
import os
import re
import datetime
import time
from hubmap_sdk import Entity, EntitySdk
from werkzeug import utils
from operator import itemgetter
from threading import Thread

from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper
from hubmap_commons import string_helper
from atlas_consortia_commons.rest import *
from atlas_consortia_commons.rest import abort_bad_req, abort_forbidden, abort_not_found
from atlas_consortia_commons.string import equals
from atlas_consortia_commons.object import enum_val_lower

from lib.exceptions import ResponseException
from lib.file_upload_helper import UploadFileHelper
from lib import get_globus_url
from lib.datacite_doi_helper import DataCiteDoiHelper
from lib.neo4j_helper import Neo4jHelper
from routes.validation import set_file_details

entity_CRUD_blueprint = Blueprint('entity_CRUD', __name__)
logger = logging.getLogger(__name__)

# Local modules
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper
from routes.entity_CRUD.dataset_helper import DatasetHelper
from routes.entity_CRUD.constraints_helper import *
from routes.auth import get_auth_header, get_auth_header_dict

from lib.ontology import Ontology, get_dataset_types_ep, get_organ_types_ep
from lib.file import get_csv_records, get_base_path, check_upload, ln_err, files_exist
from lib.services import get_associated_sources_from_dataset


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


@entity_CRUD_blueprint.route('/datasets/components', methods=['POST'])
def multiple_components():
    if not request.is_json:
        return Response("json request required", 400)
    try:
        component_request = request.json
        auth_helper = AuthHelper.configured_instance(current_app.config['APP_CLIENT_ID'], current_app.config['APP_CLIENT_SECRET'])
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        if isinstance(auth_tokens, Response):
            return(auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        elif 'nexus_token' in auth_tokens:
            token = auth_tokens['nexus_token']
        else:
            return(Response("Valid nexus auth token required", 401))

        # Check that `dataset_link_abs_dir` exists for both datasets and that it is a valid directory
        json_data_dict = request.get_json()
        for dataset in json_data_dict.get('datasets'):
            if 'dataset_link_abs_dir' in dataset:
                if not os.path.exists(dataset['dataset_link_abs_dir']):
                    return Response(f"The filepath specified with 'dataset_link_abs_dir' does not exist: {dataset['dataset_link_abs_dir']}", 400)
                if not os.path.isdir(dataset['dataset_link_abs_dir']):
                    return Response(f"The filepath specified with 'dataset_link_abs_dir is not a directory: {dataset['dataset_link_abs_dir']}", 400)
            else:
                return Response("Required field 'dataset_link_abs_dir' is missing from dataset", 400)

            if not 'contains_human_genetic_sequences' in dataset:
                return Response("Missing required keys in request json: datasets.contains_human_genetic_sequences", 400)

        requested_group_uuid = None
        if 'group_uuid' in component_request:
            requested_group_uuid = component_request['group_uuid']

        ingest_helper = IngestFileHelper(current_app.config)
        requested_group_uuid = auth_helper.get_write_group_uuid(token, requested_group_uuid)
        component_request['group_uuid'] = requested_group_uuid
        post_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'datasets/components'
        response = requests.post(post_url, json = component_request, headers = {'Authorization': 'Bearer ' + token, 'X-SenNet-Application':'ingest-api' }, verify = False)
        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_datasets_list = response.json()

        for dataset in new_datasets_list:
            # The property `dataset_link_abs_dir` will contain the filepath to the existing directory located inside the primary multi-assay
            # directory. We need to create a symlink to the aforementioned directory at the path for the newly created datsets.
            if 'dataset_link_abs_dir' in dataset:
                new_directory_path = ingest_helper.get_dataset_directory_absolute_path(dataset, requested_group_uuid, dataset['uuid'])
                logger.info(
                    f"Creating a directory as: {new_directory_path} with a symbolic link to: {dataset['dataset_link_abs_dir']}")
                os.symlink(dataset['dataset_link_abs_dir'], new_directory_path, True)
            else:
                return Response("Required field 'dataset_link_abs_dir' is missing from dataset", 400)

        return jsonify(new_datasets_list)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + " Check the logs", 500)


@entity_CRUD_blueprint.route('/sources/bulk/validate', methods=['POST'])
def bulk_sources_upload_and_validate():
    return _bulk_upload_and_validate(Ontology.ops().entities().SOURCE)


@entity_CRUD_blueprint.route('/sources/bulk/register', methods=['POST'])
def create_sources_from_bulk():
    header = get_auth_header()
    check_results = _check_request_for_bulk()
    if isinstance(check_results.get('csv_records'), Response):
        return check_results.get('csv_records')
    group_uuid = check_results.get('group_uuid')
    headers, records = itemgetter('headers', 'records')(check_results.get('csv_records'))
    valid_file = validate_sources(headers, records)

    if type(valid_file) is list:
        return rest_bad_req(valid_file)
    entity_response = {}
    status_codes = []
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
            status_codes.append(r.status_code)
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                entity_created = True
        return _send_response_on_file(entity_created, entity_failed_to_create, entity_response, _get_status_code__by_priority(status_codes))


@entity_CRUD_blueprint.route('/samples/bulk/validate', methods=['POST'])
def bulk_samples_upload_and_validate():
    return _bulk_upload_and_validate(Ontology.ops().entities().SAMPLE)


@entity_CRUD_blueprint.route('/samples/bulk/register', methods=['POST'])
def create_samples_from_bulk():
    header = get_auth_header()
    check_results = _check_request_for_bulk()
    if isinstance(check_results.get('csv_records'), Response):
        return check_results.get('csv_records')
    group_uuid = check_results.get('group_uuid')
    headers, records = itemgetter('headers', 'records')(check_results.get('csv_records'))

    valid_file = validate_samples(headers, records, header)

    if type(valid_file) is list:
        return rest_bad_req(valid_file)
    entity_response = {}
    status_codes = []
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
            status_codes.append(r.status_code)
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                entity_created = True
        return _send_response_on_file(entity_created, entity_failed_to_create, entity_response, _get_status_code__by_priority(status_codes))


@entity_CRUD_blueprint.route('/datasets/bulk/validate', methods=['POST'])
def bulk_datasets_upload_and_validate():
    return _bulk_upload_and_validate(Ontology.ops().entities().DATASET)


@entity_CRUD_blueprint.route('/datasets/bulk/register', methods=['POST'])
def create_datasets_from_bulk():
    header = get_auth_header()
    check_results = _check_request_for_bulk()
    if isinstance(check_results.get('csv_records'), Response):
        return check_results.get('csv_records')
    group_uuid = check_results.get('group_uuid')
    headers, records = itemgetter('headers', 'records')(check_results.get('csv_records'))

    # Ancestor_id can contain multiple entries. This must be split by comma before validating
    for record in records:
        if record.get('ancestor_id'):
            ancestor_id_string = record['ancestor_id']
            ancestor_id_list = ancestor_id_string.split(',')
            ancestor_stripped = []
            for ancestor in ancestor_id_list:
                ancestor_stripped.append(ancestor.strip())
            record['ancestor_id'] = ancestor_stripped
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
    status_codes = []
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
            new_dataset = r.json()
            entity_response[row_num] = new_dataset
            row_num = row_num + 1
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                ingest_helper = IngestFileHelper(current_app.config)
                ingest_helper.create_dataset_directory(new_dataset, group_uuid, new_dataset['uuid'])
                entity_created = True
            status_codes.append(r.status_code)
        return _send_response_on_file(entity_created, entity_failed_to_create, entity_response, _get_status_code__by_priority(status_codes))


@entity_CRUD_blueprint.route('/uploads/<ds_uuid>/file-system-abs-path', methods=['GET'])
@entity_CRUD_blueprint.route('/datasets/<ds_uuid>/file-system-abs-path', methods=['GET'])
def get_file_system_absolute_path(ds_uuid: str):
    try:
        ingest_helper = IngestFileHelper(current_app.config)
        return jsonify({'path': get_ds_path(ds_uuid, ingest_helper)}), 200
    except ResponseException as re:
        return re.response
    except HTTPException as hte:
        return Response(f"Error while getting file-system-abs-path for {ds_uuid}: " +
                        hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while retrieving entity {ds_uuid}: " + str(e), 500)


@entity_CRUD_blueprint.route('/entities/file-system-rel-path', methods=['POST'])
def get_file_system_relative_path():
    ds_uuid_list = request.json
    out_list = []
    error_id_list = []
    auth_helper_instance = AuthHelper.instance()
    for ds_uuid in ds_uuid_list:
        try:
            ent_recd = {}
            ent_recd['id'] = ds_uuid
            dset = __get_entity(ds_uuid, auth_header="Bearer " + auth_helper_instance.getProcessSecret())
            ent_type_m = __get_dict_prop(dset, 'entity_type')
            ent_recd['entity_type'] = ent_type_m
            group_uuid = __get_dict_prop(dset, 'group_uuid')
            if ent_type_m is None or ent_type_m.strip() == '':
                error_id = {'id': ds_uuid, 'message': 'id not for Dataset, Publication or Upload', 'status_code': 400}
                error_id_list.append(error_id)
            ent_type = ent_type_m.lower().strip()
            ingest_helper = IngestFileHelper(current_app.config)
            if ent_type == 'upload':
                path = ingest_helper.get_upload_directory_relative_path(group_uuid=group_uuid, upload_uuid=dset['uuid'])
            elif get_entity_type_instanceof(ent_type, 'Dataset', auth_header="Bearer " + auth_helper_instance.getProcessSecret()):
                is_phi = __get_dict_prop(dset, 'contains_human_genetic_sequences')
                if group_uuid is None:
                    error_id = {'id': ds_uuid, 'message': 'Unable to find group uuid on dataset', 'status_code': 400}
                    error_id_list.append(error_id)
                if is_phi is None:
                    error_id = {'id': ds_uuid,
                                'message': f"contains_human_genetic_sequences is not set on {ent_type} dataset",
                                'status_code': 400}
                    error_id_list.append(error_id)
                path = ingest_helper.get_dataset_directory_relative_path(dset, group_uuid, dset['uuid'])
            else:
                error_id = {'id': ds_uuid, 'message': f'Unhandled entity type, must be Upload, Publication or Dataset, '
                                                      f'found {ent_type_m}', 'status_code': 400}
                error_id_list.append(error_id)
            ent_recd['rel_path'] = path['rel_path']
            ent_recd['globus_endpoint_uuid'] = path['globus_endpoint_uuid']
            ent_recd['uuid'] = (__get_dict_prop(dset, 'uuid'))
            ent_recd['sennet_id'] = (__get_dict_prop(dset, 'sennet_id'))
            out_list.append(ent_recd)
        except HTTPException as hte:
            error_id = {'id': ds_uuid, 'message': hte.get_description(), 'status_code': hte.get_status_code()}
            error_id_list.append(error_id)
        except Exception as e:
            logger.error(e, exc_info=True)
            error_id = {'id': ds_uuid, 'message': str(e), 'status_code': 500}
            error_id_list.append(error_id)
    if len(error_id_list) > 0:
        status_code = 400
        for each in error_id_list:
            if each['status_code'] == 500:
                status_code = 500
        return jsonify(error_id_list), status_code
    return jsonify(out_list), 200


@entity_CRUD_blueprint.route('/entities/<entity_uuid>', methods = ['GET'])
def get_entity(entity_uuid):
    try:
        entity = __get_entity(entity_uuid, auth_header = request.headers.get("AUTHORIZATION"))
        return jsonify (entity), 200
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while retrieving entity {entity_uuid}: " + str(e), 500)


def get_ds_path(ds_uuid: str,
                ingest_helper: IngestFileHelper) -> str:
    """Get the path to the dataset files"""
    dset = __get_entity(ds_uuid, auth_header=request.headers.get("AUTHORIZATION"))
    ent_type = __get_dict_prop(dset, 'entity_type')
    group_uuid = __get_dict_prop(dset, 'group_uuid')
    if ent_type is None or ent_type.strip() == '':
        raise ResponseException(f"Entity with uuid:{ds_uuid} needs to be a Dataset or Upload.", 400)
    if ent_type.lower().strip() == 'upload':
        return ingest_helper.get_upload_directory_absolute_path(group_uuid=group_uuid, upload_uuid=ds_uuid)
    is_phi = __get_dict_prop(dset, 'contains_human_genetic_sequences')
    if ent_type is None or not (ent_type.lower().strip() == 'dataset' or ent_type.lower().strip() == 'publication'):
        raise ResponseException(f"Entity with uuid:{ds_uuid} is not a Dataset, Publication or Upload", 400)
    if group_uuid is None:
        raise ResponseException(f"Unable to find group uuid on dataset {ds_uuid}", 400)
    if is_phi is None:
        raise ResponseException(f"Contains_human_genetic_sequences is not set on dataset {ds_uuid}", 400)
    return ingest_helper.get_dataset_directory_absolute_path(dset, group_uuid, ds_uuid)


def __get_entity(entity_uuid, auth_header=None):
    if auth_header is None:
        headers = None
    else:
        headers = {'Authorization': auth_header, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    get_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) +\
              'entities/' + entity_uuid

    response = requests.get(get_url, headers=headers, verify=False)
    if response.status_code != 200:
        err_msg = f"Error while calling {get_url} status code:{response.status_code}  message:{response.text}"
        logger.error(err_msg)
        raise HTTPException(err_msg, response.status_code)

    return response.json()


def __get_dict_prop(dic, prop_name):
    if prop_name not in dic:
        return None
    val = dic[prop_name]
    if isinstance(val, str) and val.strip() == '':
        return None
    return val


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

        entity_api_url = commons_file_helper.ensureTrailingSlashURL(
            current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + uuid

        if isinstance(auth_tokens, Response):
            return auth_tokens
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        else:
            return Response("Valid auth token required", 401)

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

    def call_entity_api():
        return requests.put(entity_api_url, json=dataset_request, headers=get_auth_header_dict(token), verify=False)

    def entity_error_msg(resp):
        msg = f"call to {entity_api_url} failed with code:{resp.status_code} message:" + resp.text
        logger.error(msg)
        return msg

    def change_status_and_call_entity_api(message=None, status='Error'):
        try:
            if message is not None:
                dataset_request['pipeline_message'] = message
            if status is not None:
                dataset_request['status'] = status

            return call_entity_api()

        except HTTPException as hte2:
            logger.error(hte2)
            return Response(f"HTTPException while updating Dataset: {str(hte2)}. Check the logs.", 500)

    # Datasets without directories or files fail an initial pipeline check so these never get set as 'processing' and just error out.
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
                response = change_status_and_call_entity_api(status='Processing')
            else:
                error_message = 'Failed call to AirFlow HTTP Response: ' + str(r.status_code) + ' msg: ' + str(r.text)
                logger.error(error_message)
                response = change_status_and_call_entity_api(error_message)
            if not r.status_code == 200:
                entity_error_msg(response)
            else:
                logger.info(response.json())
        except HTTPException as hte:
            logger.error(hte)
            change_status_and_call_entity_api(f"HTTPException: {str(hte)}")
        except Exception as e2:
            logger.error(e2, exc_info=True)
            change_status_and_call_entity_api(f"Exception: {str(e2)}")

    thread = Thread(target=call_airflow)
    thread.start()
    return Response("Request of Dataset Submission Accepted", 202)


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


def run_query(query, results, i):
    logger.info(query)
    with Neo4jHelper.get_instance().session() as session:
        results[i] = session.run(query).data()


@entity_CRUD_blueprint.route('/datasets/data-status', methods=['GET'])
def dataset_data_status():
    organ_types_dict = Ontology.ops(as_data_dict=True, key='rui_code', val_key='term').organ_types()
    all_datasets_query = (
        "MATCH (ds:Dataset)-[:WAS_GENERATED_BY]->(:Activity)-[:USED]->(ancestor) "
        "RETURN ds.uuid AS uuid, ds.group_name AS group_name, ds.dataset_type AS dataset_type, "
        "ds.sennet_id AS sennet_id, ds.lab_dataset_id AS provider_experiment_id, ds.status AS status, "
        "ds.last_modified_timestamp AS last_touch, ds.published_timestamp AS published_timestamp, ds.data_access_level AS data_access_level, "
        "ds.assigned_to_group_name AS assigned_to_group_name, ds.ingest_task AS ingest_task, COLLECT(DISTINCT ds.uuid) AS datasets, "
        "COALESCE(ds.contributors IS NOT NULL) AS has_contributors, COALESCE(ds.contacts IS NOT NULL) AS has_contacts, "
        "ancestor.entity_type AS ancestor_entity_type"
    )

    organ_query = (
        "MATCH (ds:Dataset)-[*]->(o:Sample {sample_category: 'Organ'}) "
        "WHERE (ds)-[:WAS_GENERATED_BY]->(:Activity) "
        "RETURN DISTINCT ds.uuid AS uuid, o.organ AS organ, o.sennet_id as organ_sennet_id, o.uuid as organ_uuid "
    )

    source_query = (
        "MATCH (ds:Dataset)-[*]->(dn:Source) "
        "WHERE (ds)-[:WAS_GENERATED_BY]->(:Activity) "
        "RETURN DISTINCT ds.uuid AS uuid, "
        "COLLECT(DISTINCT dn.sennet_id) AS source_sennet_id, "
        "COLLECT(DISTINCT dn.source_type) AS source_type, "
        "COLLECT(DISTINCT dn.lab_source_id) AS source_lab_id, COALESCE(dn.metadata IS NOT NULL) AS has_donor_metadata"
    )

    descendant_datasets_query = (
        "MATCH (dds:Dataset)-[*]->(ds:Dataset)-[:WAS_GENERATED_BY]->(:Activity)-[:USED]->(:Sample) "
        "RETURN DISTINCT ds.uuid AS uuid, COLLECT(DISTINCT dds.sennet_id) AS descendant_datasets"
    )

    has_rui_query = (
        "MATCH (ds:Dataset) "
        "WHERE (ds)-[:WAS_GENERATED_BY]->(:Activity) "
        "WITH ds, [(ds)-[*]->(s:Sample) | s.rui_location] AS rui_locations "
        "RETURN ds.uuid AS uuid, any(rui_location IN rui_locations WHERE rui_location IS NOT NULL) AS has_rui_info"
    )

    displayed_fields = [
        "sennet_id", "group_name", "status", "organ", "provider_experiment_id", "last_touch", "has_contacts",
        "has_contributors", "dataset_type", "source_sennet_id", "source_lab_id",
        "has_dataset_metadata", "has_donor_metadata", "descendant_datasets", "upload", "has_rui_info", "globus_url", "portal_url", "ingest_url",
        "has_data", "organ_sennet_id", "assigned_to_group_name", "ingest_task",
    ]

    queries = [all_datasets_query, organ_query, source_query, descendant_datasets_query, has_rui_query]
    results = [None] * len(queries)
    threads = []
    for i, query in enumerate(queries):
        thread = Thread(target=run_query, args=(query, results, i))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    output_dict = {}
    # Here we specifically indexed the values in 'results' in case certain threads completed out of order
    all_datasets_result = results[0]
    organ_result = results[1]
    source_result = results[2]
    descendant_datasets_result = results[3]
    has_rui_result = results[4]

    for dataset in all_datasets_result:
        output_dict[dataset['uuid']] = dataset
    for dataset in organ_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['organ'] = dataset['organ']
            output_dict[dataset['uuid']]['organ_sennet_id'] = dataset['organ_sennet_id']
            output_dict[dataset['uuid']]['organ_uuid'] = dataset['organ_uuid']
    for dataset in source_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['source_sennet_id'] = dataset['source_sennet_id']
            output_dict[dataset['uuid']]['source_type'] = dataset['source_type']
            # output_dict[dataset['uuid']]['source_submission_id'] = dataset['source_submission_id']
            output_dict[dataset['uuid']]['source_lab_id'] = dataset['source_lab_id']
            output_dict[dataset['uuid']]['has_donor_metadata'] = dataset['has_donor_metadata']
    for dataset in descendant_datasets_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['descendant_datasets'] = dataset['descendant_datasets']
    for dataset in has_rui_result:
        if output_dict.get(dataset['uuid']):
            output_dict[dataset['uuid']]['has_rui_info'] = dataset['has_rui_info']

    combined_results = []
    for uuid in output_dict:
        combined_results.append(output_dict[uuid])

    for dataset in combined_results:
        globus_url = get_globus_url(dataset.get('data_access_level'), dataset.get('group_name'), dataset.get('uuid'))
        dataset['globus_url'] = globus_url
        portal_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['PORTAL_URL']) + 'dataset' + '/' + dataset[
            'uuid']
        dataset['portal_url'] = portal_url
        ingest_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['INGEST_URL']) + 'dataset' + '/' + dataset[
            'uuid']
        dataset['ingest_url'] = ingest_url
        if dataset.get('organ_uuid'):
            organ_portal_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['PORTAL_URL']) + 'sample' + '/' + dataset['organ_uuid']
            dataset['organ_portal_url'] = organ_portal_url
        else:
            dataset['organ_portal_url'] = ""
        last_touch = dataset['last_touch'] if dataset['published_timestamp'] is None else dataset['published_timestamp']
        dataset['last_touch'] = str(datetime.datetime.utcfromtimestamp(last_touch/1000))
        dataset['is_primary'] = dataset_is_primary(dataset.get('uuid'))

        has_data = files_exist(dataset.get('uuid'), dataset.get('data_access_level'), dataset.get('group_name'))
        has_dataset_metadata = files_exist(dataset.get('uuid'), dataset.get('data_access_level'), dataset.get('group_name'), metadata=True)
        dataset['has_data'] = has_data
        dataset['has_dataset_metadata'] = has_dataset_metadata

        for prop in dataset:
            if isinstance(dataset[prop], list):
                dataset[prop] = ", ".join(dataset[prop])
            if isinstance(dataset[prop], (bool, int)):
                dataset[prop] = str(dataset[prop])
            if isinstance(dataset[prop], str) and \
                    len(dataset[prop]) >= 2 and \
                    dataset[prop][0] == "[" and dataset[prop][-1] == "]":
                prop_as_list = string_helper.convert_str_literal(dataset[prop])
                if len(prop_as_list) > 0:
                    dataset[prop] = prop_as_list
                else:
                    dataset[prop] = ""
            if dataset[prop] is None:
                dataset[prop] = ""
        for field in displayed_fields:
            if dataset.get(field) is None:
                dataset[field] = ""
        if (dataset.get('organ') and dataset['organ'].upper() in ['AD', 'BD', 'BM', 'BS', 'MU', 'OT']) or (dataset.get('source_type') and dataset['source_type'].upper() in ['MOUSE', 'MOUSE ORGANOID']):
            dataset['has_rui_info'] = "not-applicable"
        if dataset.get('organ') and dataset.get('organ') in organ_types_dict:
            dataset['organ'] = organ_types_dict[dataset['organ']]

    return jsonify(combined_results)


@entity_CRUD_blueprint.route('/datasets/<identifier>/publish', methods = ['PUT'])
def publish_datastage(identifier):
    try:
        auth_helper = AuthHelper.instance()

        user_info = auth_helper.getUserInfoUsingRequest(request, getGroups=True)
        if user_info is None:
            return Response("Unable to obtain user information for auth token", 401)
        if isinstance(user_info, Response):
            return user_info

        if 'hmgroupids' not in user_info:
            abort_forbidden('User has no valid group information to authorize publication.')
        if not auth_helper.has_data_admin_privs(auth_helper.getUserTokenFromRequest(request, getGroups=True)):
            abort_forbidden('User must be a member of the SenNet Data Admin group to publish data.')

        if identifier is None or len(identifier) == 0:
            abort_bad_req('identifier parameter is required to publish a dataset')

        url = commons_file_helper.ensureTrailingSlashURL(current_app.config['UUID_WEBSERVICE_URL']) + "uuid/" + identifier
        r = requests.get(url, headers={'Authorization': request.headers["AUTHORIZATION"]})
        if r.ok is False:
            abort_not_found("Cannot find specimen with identifier: " + identifier)

        dataset_uuid = json.loads(r.text)['hm_uuid']
        is_primary = dataset_is_primary(dataset_uuid)
        suspend_indexing_and_acls = string_helper.isYes(request.args.get('suspend-indexing-and-acls'))
        no_indexing_and_acls = False
        if suspend_indexing_and_acls:
            no_indexing_and_acls = True

        sources_to_reindex = []
        with Neo4jHelper.get_instance().session() as neo_session:
            # look at all of the ancestors
            # gather uuids of ancestors that need to be switched to public access_level
            # grab the id of the source ancestor to use for reindexing
            q = f"MATCH (dataset:Dataset {{uuid: '{dataset_uuid}'}})-[:WAS_GENERATED_BY]->(e1)-[:USED|WAS_GENERATED_BY*]->(all_ancestors:Entity) RETURN distinct all_ancestors.uuid as uuid, all_ancestors.entity_type as entity_type, all_ancestors.dataset_type as dataset_type, all_ancestors.data_access_level as data_access_level, all_ancestors.status as status, all_ancestors.metadata as metadata"
            rval = neo_session.run(q).data()
            uuids_for_public = []
            has_source = False
            for node in rval:
                uuid = node['uuid']
                entity_type = node['entity_type']
                data_access_level = node['data_access_level']
                status = node['status']
                metadata = node.get("metadata")
                if entity_type == 'Sample':
                    if data_access_level != 'public':
                        uuids_for_public.append(uuid)
                elif entity_type == 'Source':
                    has_source = True
                    if is_primary:
                        if metadata is None or metadata.strip() == '':
                            return jsonify({"error": f"source.metadata is missing for {dataset_uuid}"}), 400
                        metadata = metadata.replace("'", '"')
                        metadata_dict = json.loads(metadata)
                        living_donor = True
                        organ_donor = True
                        if metadata_dict.get('organ_donor_data') is None:
                            living_donor = False
                        if metadata_dict.get('living_donor_data') is None:
                            organ_donor = False
                        if (organ_donor and living_donor) or (not organ_donor and not living_donor):
                            return jsonify({"error": f"source.metadata.organ_donor_data or "
                                                     f"source.metadata.living_donor_data required. "
                                                     f"Both cannot be None. Both cannot be present. Only one."}), 400
                    sources_to_reindex.append(uuid)
                    if data_access_level != 'public':
                        uuids_for_public.append(uuid)
                elif entity_type == 'Dataset':
                    if status != 'Published':
                        abort_bad_req(f"{dataset_uuid} has an ancestor dataset that has not been Published. Will not Publish. Ancestor dataset is: {uuid}")

            if has_source is False:
                abort_bad_req(f"{dataset_uuid}: no source found for dataset, will not Publish")

            # get info for the dataset to be published
            q = (
                f"MATCH (e:Dataset {{uuid: '{dataset_uuid}'}}) RETURN "
                "e.uuid as uuid, e.entity_type as entitytype, e.status as status, "
                "e.data_access_level as data_access_level, e.group_uuid as group_uuid, "
                "e.contacts as contacts, e.contributors as contributors"
            )
            if is_primary:
                q += ", e.ingest_metadata as ingest_metadata"

            rval = neo_session.run(q).data()
            dataset_status = rval[0]['status']
            dataset_entitytype = rval[0]['entitytype']
            dataset_data_access_level = rval[0]['data_access_level']
            dataset_group_uuid = rval[0]['group_uuid']
            dataset_contacts = rval[0]['contacts']
            dataset_contributors = rval[0]['contributors']
            dataset_ingest_metadata_dict = None
            if is_primary:
                dataset_ingest_metadata = rval[0].get('ingest_metadata')
                if dataset_ingest_metadata is not None:
                    dataset_ingest_metadata_dict: dict = string_helper.convert_str_literal(dataset_ingest_metadata)
                logger.info(f"publish_datastage; ingest_metadata: {dataset_ingest_metadata_dict}")

            if not get_entity_type_instanceof(dataset_entitytype, 'Dataset', auth_header="Bearer " + auth_helper.getProcessSecret()):
                abort_bad_req(f"{dataset_uuid} is not a dataset will not Publish, entity type is {dataset_entitytype}")
            if not dataset_status == 'QA':
                abort_bad_req(f"{dataset_uuid} is not in QA state will not Publish, status is {dataset_status}")

            auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
            entity_instance = EntitySdk(token=auth_tokens, service_url=current_app.config['ENTITY_WEBSERVICE_URL'])
            entity = entity_instance.get_entity_by_id(dataset_uuid)
            entity_dict = obj_to_dict(entity)

            dataset_types_edp = list(Ontology.ops(as_data_dict=True).dataset_types().values())
            has_entity_lab_processed_dataset_type: bool = entity_dict.get('dataset_type') in dataset_types_edp

            logger.info(f'is_primary: {is_primary}; has_entity_lab_processed_dataset_type: {has_entity_lab_processed_dataset_type}')

            if is_primary or has_entity_lab_processed_dataset_type:
                if dataset_contacts is None or dataset_contributors is None:
                    abort_bad_req(f"{dataset_uuid} missing contacts or contributors. Must have at least one of each")
                dataset_contacts = dataset_contacts.replace("'", '"')
                dataset_contributors = dataset_contributors.replace("'", '"')
                if len(json.loads(dataset_contacts)) < 1 or len(json.loads(dataset_contributors)) < 1:
                    abort_bad_req(f"{dataset_uuid} missing contacts or contributors. Must have at least one of each")

            ingest_helper = IngestFileHelper(current_app.config)
            ds_path = ingest_helper.dataset_directory_absolute_path(dataset_data_access_level, dataset_group_uuid, dataset_uuid, False)

            md_file = os.path.join(ds_path, "metadata.json")
            json_object = entity_json_dumps(entity, auth_tokens, entity_instance)
            logger.info(f"publish_datastage; writing metadata.json file: '{md_file}'; containing: '{json_object}'")
            try:
                with open(md_file, "w") as outfile:
                    outfile.write(json_object)
            except Exception as e:
                logger.exception(f"Fatal error while writing md_file {md_file}; {str(e)}")
                return jsonify({"error": f"{dataset_uuid} problem writing metadata.json file."}), 500

            data_access_level = dataset_data_access_level
            # if consortium access level convert to public dataset, if protected access leave it protected
            if dataset_data_access_level == 'consortium':
                # before moving check to see if there is currently a link for the dataset in the assets directory
                asset_dir = ingest_helper.dataset_asset_directory_absolute_path(dataset_uuid)
                asset_dir_exists = os.path.exists(asset_dir)
                ingest_helper.move_dataset_files_for_publishing(dataset_uuid, dataset_group_uuid, 'consortium')
                uuids_for_public.append(dataset_uuid)
                data_access_level = 'public'
                if asset_dir_exists:
                    ingest_helper.relink_to_public(dataset_uuid)

            acls_cmd = ingest_helper.set_dataset_permissions(dataset_uuid, dataset_group_uuid, data_access_level,
                                                             True, no_indexing_and_acls)

            # Generating DOI's for lab processed/derived data as well as IEC/pipeline/airflow processed/derived data).
            if is_primary or has_entity_lab_processed_dataset_type:
                # DOI gets generated here
                # Note: moved dataset title auto generation to entity-api - Zhou 9/29/2021
                datacite_doi_helper = DataCiteDoiHelper()

                try:
                    datacite_doi_helper.create_dataset_draft_doi(entity_dict, check_publication_status=False)
                except Exception as e:
                    logger.exception(f"Exception while creating a draft doi for {dataset_uuid}: {e}")
                    return jsonify({"error": f"Error occurred while trying to create a draft doi for {dataset_uuid}. {e}"}), 500

                # This will make the draft DOI created above 'findable'....
                try:
                    doi_info = datacite_doi_helper.move_doi_state_from_draft_to_findable(entity_dict, auth_tokens)
                except Exception as e:
                    logger.exception(f"Exception while creating making doi findable and saving to entity for {dataset_uuid}: {e}")
                    return jsonify({"error": f"Error occurred while trying to change doi draft state to findable doi for {dataset_uuid}. {e}"}), 500

            doi_update_clause = ""
            if doi_info is not None:
                doi_update_clause = f", e.registered_doi = '{doi_info['registered_doi']}', e.doi_url = '{doi_info['doi_url']}'"

            # set up a status_history list to add a "Published" entry to below
            status_history_list = []
            status_history_str = rval[0].get('status_history')
            if status_history_str is not None:
                status_history_list = string_helper.convert_str_literal(status_history_str)

            # add Published status change to status history
            status_update = {
               "status": "Published",
               "changed_by_email": user_info['email'],
               "change_timestamp": "@#TIMESTAMP#@"
            }
            status_history_list.append(status_update)
            # convert from list to string that is used for storage in database
            new_status_history_str = string_helper.convert_py_obj_to_string(status_history_list)
            # substitute the TIMESTAMP function to let Neo4j set the change_timestamp value of this status change record
            status_history_with_timestamp = new_status_history_str.replace("'@#TIMESTAMP#@'", '" + TIMESTAMP() + "')
            status_history_update_clause = f', e.status_history = "{status_history_with_timestamp}"'

            # set dataset status to published and set the last modified user info and user who published
            update_q = "match (e:Entity {uuid:'" + dataset_uuid + "'}) set e.status = 'Published', e.last_modified_user_sub = '" + \
                       user_info['sub'] + "', e.last_modified_user_email = '" + user_info[
                           'email'] + "', e.last_modified_user_displayname = '" + user_info[
                           'name'] + "', e.last_modified_timestamp = TIMESTAMP(), e.published_timestamp = TIMESTAMP(), e.published_user_email = '" + \
                       user_info['email'] + "', e.published_user_sub = '" + user_info[
                           'sub'] + "', e.published_user_displayname = '" + user_info['name'] + "'" + doi_update_clause + status_history_update_clause

            logger.info(dataset_uuid + "\t" + dataset_uuid + "\tNEO4J-update-base-dataset\t" + update_q)
            neo_session.run(update_q)

            # triggers a call to entity-api/flush-cache
            entity_instance.clear_cache(dataset_uuid)

            # if all else worked set the list of ids to public that need to be public
            if len(uuids_for_public) > 0:
                id_list = string_helper.listToCommaSeparated(uuids_for_public, quoteChar="'")
                update_q = "match (e:Entity) where e.uuid in [" + id_list + "] set e.data_access_level = 'public'"
                logger.info(identifier + "\t" + dataset_uuid + "\tNEO4J-update-ancestors\t" + update_q)
                neo_session.run(update_q)
                for e_id in uuids_for_public:
                    entity_instance.clear_cache(e_id)

        if no_indexing_and_acls:
            r_val = {'acl_cmd': acls_cmd, 'sources_for_indexing': sources_to_reindex}
        else:
            r_val = {'acl_cmd': '', 'sources_for_indexing': []}

        if not no_indexing_and_acls:
            for source_uuid in sources_to_reindex:
                try:
                    rspn = requests.put(current_app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + source_uuid, headers={'Authorization': request.headers["AUTHORIZATION"]})
                    logger.info(f"Publishing {identifier} indexed source {source_uuid} with status {rspn.status_code}")
                except Exception:
                    logger.exception(f"While publishing {identifier} Error happened when calling reindex web service for source {source_uuid}")

        return Response(json.dumps(r_val), 200, mimetype='application/json')

    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a dataset: " + str(e) + "  Check the logs", 500)


def dataset_is_primary(dataset_uuid):
    with Neo4jHelper.get_instance().session() as neo_session:
        q = (f"MATCH (ds:Dataset {{uuid: '{dataset_uuid}'}})-[:WAS_GENERATED_BY]->(a:Activity) WHERE NOT toLower(a.creation_action) ENDS WITH 'process' RETURN ds.uuid")
        result = neo_session.run(q).data()
        if len(result) == 0:
            return False
        return True


####################################################################################################
## Uploads API Endpoints
####################################################################################################

# This creates a new protected Uploads folder once a user creates a new Uploads datagroup
#
#
# example url:  https://my.endpoint.server/uploads
# inputs:
#      - The title of the new folder
#      - The UUID
#      - A valid nexus token in a authorization bearer header
#
# returns
#      200 json with Details about the new folder (@TODO: paste in once authed again)
#      400 if invalid json sent
#      401 if user does not have hubmap read access or the token is invalid
#
# Example json response:
#                  {{
#                         "created_by_user_displayname": "Eris Pink",
#                         "created_by_user_email": "mycoolemail@aolonline.co",
#                         "created_by_user_sub": "12345678-abba-2468-wdwa-6484IDKSGGFF",
#                         "created_timestamp": 1587414020,
#                         "entity_type": "Upload",
#                         "group_name": "IEC Testing Group",
#                         "group_uuid": "UUID-OF-GROUP-HERE-0e006b0001e9",
#                         "sennet_id": "SNT664.XGCF.687",
#                         "last_modified_timestamp": 1587414020,
#                         "last_modified_user_displayname": "E Pink",
#                         "last_modified_user_email": "Jmycoolemail@aolonline.co",
#                         "last_modified_user_sub": "76f777all-abba-6971-hehe-125ea519865",
#                         "status": "New",
#                         "title": "TestTitle",
#                         "uuid": "4a583209bfe9ad6cda851d913ac44833915"
#                    }

@entity_CRUD_blueprint.route('/uploads', methods=['POST'])
def create_uploadstage():
    if not request.is_json:
        return Response("json request required", 400)
    try:
        upload_request = request.json
        auth_helper = AuthHelper.configured_instance(current_app.config['APP_CLIENT_ID'], current_app.config['APP_CLIENT_SECRET'])
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        if isinstance(auth_tokens, Response):
            return(auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        elif 'groups_token' in auth_tokens:
            token = auth_tokens['groups_token']
        else:
            return(Response("Valid nexus auth token required", 401))

        requested_group_uuid = None
        if 'group_uuid' in upload_request:
            requested_group_uuid = upload_request['group_uuid']

        ingest_helper = IngestFileHelper(current_app.config)
        requested_group_uuid = auth_helper.get_write_group_uuid(token, requested_group_uuid)
        upload_request['group_uuid'] = requested_group_uuid
        post_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/upload'
        response = requests.post(post_url, json=upload_request, headers=get_auth_header_dict(token), verify=False)
        if response.status_code != 200:
            return Response(response.text, response.status_code)
        new_upload = response.json()
        ingest_helper.create_upload_directory(requested_group_uuid, new_upload['uuid'])
        return jsonify(new_upload)
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while creating a upload: " + str(e) + "  Check the logs", 500)


    #method to change the status of an Upload to "submitted"
#will also save any changes to title or description that are passed in
@entity_CRUD_blueprint.route('/uploads/<upload_uuid>/submit', methods=['PUT'])
def submit_upload(upload_uuid):
    if not request.is_json:
        return Response("json request required", 400)

    upload_changes = request.json
    upload_changes['status'] = 'Submitted'

    #get auth info to use in other calls
    #add the app specific header info
    http_headers = {
        'Authorization': request.headers["AUTHORIZATION"],
        'Content-Type': 'application/json',
        'X-SenNet-Application':'ingest-api'
    }

    update_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid
    # Disable ssl certificate verification
    resp = requests.put(update_url, headers=http_headers, json=upload_changes, verify = False)

    #disable validations stuff for now...
    ##call the AirFlow validation workflow
    #validate_url = commons_file_helper.ensureTrailingSlashURL(app.config['INGEST_PIPELINE_URL']) + 'uploads/' + upload_uuid + "/validate"
    ## Disable ssl certificate verification
    #resp = requests.put(validate_url, headers=http_headers, json=upload_changes, verify = False)
    #if resp.status_code >= 300:
    #    return Response(resp.text, resp.status_code)

    return Response(resp.text, resp.status_code)

#method to validate an Upload
#saves the upload then calls the validate workflow via
#AirFlow interface
@entity_CRUD_blueprint.route('/uploads/<upload_uuid>/validate', methods=['PUT'])
def validate_upload(upload_uuid):
    start_time = time.time()
    if not request.is_json:
        return Response("json request required", 400)

    upload_changes = request.json

    # get auth info to use in other calls
    # add the app specific header info
    http_headers = {
        'Authorization': request.headers["AUTHORIZATION"],
        'Content-Type': 'application/json',
        'X-SenNet-Application': 'ingest-api'
    }

    # update the Upload with any changes from the request
    # and change the status to "Processing", the validate
    # pipeline will update the status when finished

    # run the pipeline validation
    upload_changes['status'] = 'Processing'
    update_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid

    # Disable ssl certificate verification
    resp = requests.put(update_url, headers=http_headers, json=upload_changes, verify=False)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)
    logger.debug("--- %s seconds to update Entity API ---" % (time.time() - start_time))

    # disable validations stuff for now...
    ##call the AirFlow validation workflow
    validate_url = commons_file_helper.ensureTrailingSlashURL(
        current_app.config['INGEST_PIPELINE_URL']) + 'uploads/' + upload_uuid + "/validate"
    ## Disable ssl certificate verification
    resp2 = requests.put(validate_url, headers=http_headers, json=upload_changes, verify=False)
    if resp2.status_code >= 300:
        return Response(resp2.text, resp2.status_code)
    logger.debug("--- %s seconds to send validate request to Airflow ---" % (time.time() - start_time))

    return Response(resp.text, resp.status_code)

#method to reorganize an Upload
#saves the upload then calls the reorganize workflow via
#AirFlow interface
@entity_CRUD_blueprint.route('/uploads/<upload_uuid>/reorganize', methods=['PUT'])
def reorganize_upload(upload_uuid):

    #get auth info to use in other calls
    #add the app specific header info
    http_headers = {
        'Authorization': request.headers["AUTHORIZATION"],
        'Content-Type': 'application/json',
        'X-SenNet-Application':'ingest-api'
    }


    #update the Upload with any changes from the request
    #and change the status to "Processing", the validate
    #pipeline will update the status when finished
    upload_changes = {}
    upload_changes['status'] = 'Processing'
    update_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + upload_uuid

    # Disable ssl certificate verification
    resp = requests.put(update_url, headers=http_headers, json=upload_changes, verify = False)
    if resp.status_code >= 300:
        return Response(resp.text, resp.status_code)

    #disable validations stuff for now...
    ##call the AirFlow validation workflow
    validate_url = commons_file_helper.ensureTrailingSlashURL(current_app.config['INGEST_PIPELINE_URL']) + 'uploads/' + upload_uuid + "/reorganize"
    ## Disable ssl certificate verification
    resp2 = requests.put(validate_url, headers=http_headers, json=upload_changes, verify = False)
    if resp2.status_code >= 300:
        return Response(resp2.text, resp2.status_code)

    return Response(resp.text, resp.status_code)


@entity_CRUD_blueprint.route('/uploads/data-status', methods=['GET'])
def upload_data_status():
    all_uploads_query = (
        "MATCH (up:Upload) "
        "OPTIONAL MATCH (up)<-[:IN_UPLOAD]-(ds:Dataset) "
        "RETURN up.uuid AS uuid, up.group_name AS group_name, up.sennet_id AS sennet_id, up.status AS status, "
        "up.title AS title, up.assigned_to_group_name AS assigned_to_group_name, "
        "up.ingest_task AS ingest_task, COLLECT(DISTINCT ds.uuid) AS datasets"
    )

    displayed_fields = [
        "uuid", "group_name", "sennet_id", "status", "title", "datasets",
        "assigned_to_group_name", "ingest_task"
    ]

    with Neo4jHelper.get_instance().session() as session:
        results = session.run(all_uploads_query).data()
        for upload in results:
            globus_url = get_globus_url('protected', upload.get('group_name'), upload.get('uuid'))
            upload['globus_url'] = globus_url
            for prop in upload:
                if isinstance(upload[prop], list):
                    upload[prop] = ", ".join(upload[prop])
                if isinstance(upload[prop], (bool, int)):
                    upload[prop] = str(upload[prop])
                if isinstance(upload[prop], str) and \
                        len(upload[prop]) >= 2 and \
                        upload[prop][0] == "[" and upload[prop][-1] == "]":
                    prop_as_list = string_helper.convert_str_literal(upload[prop])
                    if len(prop_as_list) > 0:
                        upload[prop] = prop_as_list
                    else:
                        upload[prop] = ""
                if upload[prop] is None:
                    upload[prop] = ""
            for field in displayed_fields:
                if upload.get(field) is None:
                    upload[field] = ""
    # TODO: Once url parameters are implemented in the front-end for the data-status dashboard, we'll need to return a
    # TODO: link to the datasets page only displaying datasets belonging to a given upload.
    return jsonify(results)


@entity_CRUD_blueprint.route('/collections/attributes', methods=['POST'])
def collections_attributes():
    result: dict = {
        'error': None
    }
    if is_json_request():
        data = request.json
    else:
        data = request.values

    attribute = data.get('attribute')

    file_upload = check_upload(attribute)
    if file_upload.get('code') is StatusCodes.OK:
        file = file_upload.get('description')
        file_id = file.get('id')
        file = file.get('file')
        pathname = file_id + os.sep + file.filename
        result = set_file_details(pathname)
        records = get_csv_records(result.get('fullpath'))
        return rest_response(StatusCodes.OK, 'Collection Attributes',
                             records, False)
    else:
        return json.dumps(file_upload)


def _get_status_code__by_priority(codes):
    if StatusCodes.SERVER_ERR in codes:
        return StatusCodes.SERVER_ERR
    elif StatusCodes.UNACCEPTABLE in codes:
        return StatusCodes.UNACCEPTABLE
    else:
        return codes[0]

def _bulk_upload_and_validate(entity):
    header = get_auth_header()
    upload = check_upload()
    temp_id, file = itemgetter('id', 'file')(upload.get('description'))
    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    file.filename = utils.secure_filename(file.filename)
    file_location = get_base_path() + temp_id + os.sep + file.filename
    csv_records = get_csv_records(file_location)
    if isinstance(csv_records, Response):
        return csv_records
    headers, records = itemgetter('headers', 'records')(csv_records)

    if entity == Ontology.ops().entities().SOURCE:
        valid_file = validate_sources(headers, records)
    elif entity == Ontology.ops().entities().SAMPLE:
        valid_file = validate_samples(headers, records, header)
    elif entity == Ontology.ops().entities().DATASET:
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
    # Ancestor_id can contain multiple entries. This must be split by comma before validating
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


def _send_response_on_file(entity_created: bool, entity_failed_to_create: bool,
                           entity_response, status_code=StatusCodes.SERVER_ERR):
    if entity_created and not entity_failed_to_create:
        return rest_ok(entity_response)
    elif entity_created and entity_failed_to_create:
        return rest_response(StatusCodes.OK_PARTIAL, "Partial Success - Some Entities Created Successfully", entity_response)
    else:
        return rest_response(status_code, f"entity_created: {entity_created}, entity_failed_to_create: {entity_failed_to_create}", entity_response)


def _ln_err(error: str, row: int = None, column: str = None):
    return ln_err(error, row, column)


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


def is_invalid_doi(protocol):
    selection_protocol_pattern1 = re.match('^https://dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\..*$', protocol)
    selection_protocol_pattern2 = re.match('^dx\.doi\.org/[\d]+\.[\d]+/protocols\.io\..*$', protocol)
    return selection_protocol_pattern2 is None and selection_protocol_pattern1 is None


def validate_sources(headers, records):
    error_msg = []
    file_is_valid = True
    allowed_source_types = Ontology.ops(as_arr=True, cb=enum_val_lower).source_types()

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
            if is_invalid_doi(protocol):
                file_is_valid = False
                error_msg.append(_ln_err("must either be of the format `https://dx.doi.org/##.####/protocols.io.*` or `dx.doi.org/##.####/protocols.io.*`", rownum, "selection_protocol"))

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

    allowed_categories = Ontology.ops(as_arr=True, cb=enum_val_lower).specimen_categories()
    # Get the ontology classes
    SpecimenCategories = Ontology.ops().specimen_categories()
    Entities = Ontology.ops().entities()

    organ_types_codes = list(Ontology.ops(as_data_dict=True, key='rui_code', val_key='term').organ_types().keys())
    organ_types_codes.append('OT')

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
            if is_invalid_doi(protocol):
                file_is_valid = False
                error_msg.append(_ln_err("must either be of the format `https://dx.doi.org/##.####/protocols.io.*` or `dx.doi.org/##.####/protocols.io.*`", rownum, "preparation_protocol"))
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
                    error_msg.append(_ln_err(f"value must be an organ code listed at {get_organ_types_ep()}", rownum, "organ_type"))

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

    required_headers = ['ancestor_id', 'lab_id', 'doi_abstract', 'human_gene_sequences', 'dataset_type']
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(_common_ln_errs(1, field))
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(_common_ln_errs(2, field))

    dataset_types = list(Ontology.ops(as_data_dict=True).dataset_types().values())

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

            # validate dataset_type
            dataset_type_valid = True
            dataset_type = data_row['dataset_type']
            if dataset_type not in dataset_types:
                file_is_valid = False
                dataset_type_valid = False
                error_msg.append(_ln_err(f"value must be a dataset type listed at {get_dataset_types_ep()}", rownum, "dataset_type"))

            # validate ancestor_id
            ancestor_ids = data_row['ancestor_id']
            for ancestor_id in ancestor_ids:
                validation_results = validate_ancestor_id(header, ancestor_id, error_msg, rownum, valid_ancestor_ids, file_is_valid)

                file_is_valid, error_msg, ancestor_saved, resp_status_code, ancestor_dict \
                    = itemgetter('file_is_valid', 'error_msg', 'ancestor_saved', 'resp_status_code', 'ancestor_dict')(validation_results)

                if ancestor_saved or resp_status_code:

                    # prepare entity constraints for validation

                    sub_type = None
                    if dataset_type_valid:
                        sub_type = get_as_list(dataset_type)

                    entity_to_validate = build_constraint_unit(Ontology.ops().entities().DATASET, sub_type)

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
    Entities = Ontology.ops().entities()
    ancestor_entity_type = ancestor_dict['type'].lower()
    url = commons_file_helper.ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/' + ancestor_id

    ancestor_result = requests.get(url, headers=header).json()
    sub_type = None
    sub_type_val = None
    if equals(ancestor_entity_type, Entities.DATASET):
        sub_type = get_as_list(ancestor_result['dataset_type'])

    if equals(ancestor_entity_type, Entities.SAMPLE):
        sub_type = get_as_list(ancestor_result['sample_category'])
        if equals(ancestor_result['sample_category'], Ontology.ops().specimen_categories().ORGAN):
            sub_type_val = get_as_list(ancestor_result['organ'])

    ancestor_to_validate = build_constraint_unit(ancestor_entity_type, sub_type, sub_type_val)

    dict_to_validate = build_constraint(ancestor_to_validate, entity_to_validate)
    entity_constraint_list.append(dict_to_validate)

    return entity_constraint_list

def get_entity_type_instanceof(type_a, type_b, auth_header=None) -> bool:
    if type_a is None:
        return False
    headers = None
    if auth_header is not None:
        headers = {'Authorization': auth_header, 'Accept': 'application/json', 'Content-Type': 'application/json'}

    base_url: str = commons_file_helper.removeTrailingSlashURL(
        current_app.config['ENTITY_WEBSERVICE_URL'])
    get_url: str = f"{base_url}/entities/type/{type_a}/instanceof/{type_b}"

    response = requests.get(get_url, headers=headers, verify=False)
    if response.status_code != 200:
        err_msg = f"Error while calling {get_url} status code:{response.status_code}  message:{response.text}"
        logger.error(err_msg)
        raise HTTPException(err_msg, response.status_code)

    resp_json: dict = response.json()
    return resp_json['instanceof']


def obj_to_dict(obj) -> dict:
    """
    Convert the obj[ect] into a dict, but deeply.
    Note: The Python builtin 'vars()' does not work here because of the way that some of the classes
    are defined.
    """
    return json.loads(
        json.dumps(obj, default=lambda o: getattr(o, '__dict__', str(o)))
    )


def entity_json_dumps(entity: Entity, token: str, entity_sdk: EntitySdk) -> str:
    """
    Because entity and the content of the arrays returned from entity_instance.get_associated_*
    contain user defined objects we need to turn them into simple python objects (e.g., dicts, lists, str)
    before we can convert them wth json.dumps.
    Here we create an expanded version of the entity associated with the dataset_uuid and return it as a json string.
    """
    dataset_uuid = entity.get_uuid()
    entity = obj_to_dict(entity)
    entity['organs'] = obj_to_dict(entity_sdk.get_associated_organs_from_dataset(dataset_uuid))
    entity['samples'] = obj_to_dict(entity_sdk.get_associated_samples_from_dataset(dataset_uuid))
    entity['sources'] = get_associated_sources_from_dataset(dataset_uuid, token=token, as_dict=True)

    json_object = json.dumps(entity, indent=4)
    json_object += '\n'
    return json_object
