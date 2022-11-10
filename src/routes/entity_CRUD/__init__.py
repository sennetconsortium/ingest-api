import json

from flask import Blueprint, abort, jsonify, request, Response, current_app
import logging
import requests

from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons import file_helper as commons_file_helper

entity_CRUD_blueprint = Blueprint('entity_CRUD', __name__)
logger = logging.getLogger(__name__)

# Local modules
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper
from routes.entity_CRUD.dataset_helper import DatasetHelper


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
            return (auth_token)
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
        post_url = commons_file_helper.ensureTrailingSlashURL(
            current_app.config['ENTITY_WEBSERVICE_URL']) + 'entities/dataset'
        response = requests.post(post_url, json=dataset_request,
                                 headers={'Authorization': 'Bearer ' + token, 'X-SenNet-Application': 'ingest-api'},
                                 verify=False)
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
        r = requests.get(current_app.config['UUID_WEBSERVICE_URL'] + "/" + identifier,
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
