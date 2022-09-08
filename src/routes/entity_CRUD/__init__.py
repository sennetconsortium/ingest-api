from flask import Blueprint, jsonify, request, Response, current_app
import logging
import requests

from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper

entity_CRUD_blueprint = Blueprint('entity_CRUD', __name__)
logger = logging.getLogger(__name__)

# Local modules
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper

@entity_CRUD_blueprint.route('/datasets', methods=['POST'])
def create_dataset():

    if not request.is_json:
        return Response("json request required", 400)
    try:
        dataset_request = request.json
        auth_helper_instance = AuthHelper.instance()
        auth_tokens = auth_helper_instance.getAuthorizationTokens(request.headers)
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
