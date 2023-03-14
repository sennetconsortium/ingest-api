import logging

from flask import Blueprint, request, Response, current_app
from hubmap_commons import neo4j_driver
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.hm_auth import AuthHelper

from routes.entity_CRUD import IngestFileHelper
from threading import Thread
import requests
import json
from hubmap_commons import file_helper as commons_file_helper


datasets_blueprint = Blueprint('datasets', __name__)
logger = logging.getLogger(__name__)
data_admin_group_uuid = current_app.config['SENNET_DATA_ADMIN_GROUP_UUID']

try:
    neo4j_driver_instance = neo4j_driver.instance(current_app.config['NEO4J_SERVER'],
                                                  current_app.config['NEO4J_USERNAME'],
                                                  current_app.config['NEO4J_PASSWORD'])

    logger.info("Initialized neo4j_driver module successfully :)")
except Exception:
    msg = "Failed to initialize the neo4j_driver module"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)


@datasets_blueprint.route('/datasets/<uuid>/submit', methods=['PUT'])
def submit_dataset(uuid):
    if not request.is_json:
        return Response("json request required", 400)
    try:
        dataset_request = request.json
        auth_helper = AuthHelper.configured_instance(current_app.config['APP_CLIENT_ID'],
                                                     current_app.config['APP_CLIENT_SECRET'])
        ingest_helper = IngestFileHelper(current_app.config)
        auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
        if isinstance(auth_tokens, Response):
            return (auth_tokens)
        elif isinstance(auth_tokens, str):
            token = auth_tokens
        elif 'nexus_token' in auth_tokens:
            token = auth_tokens['nexus_token']
        else:
            return (Response("Valid nexus auth token required", 401))

        if 'group_uuid' in dataset_request:
            return Response(
                "Cannot specify group_uuid.  The group ownership cannot be changed after an entity has been created.",
                400)

        with neo4j_driver_instance.session() as session:
            # query Neo4j db to get the group_uuid
            stmt = "match (d:Dataset {uuid:'" + uuid.strip() + "'}) return d.group_uuid as group_uuid"
            records = session.run(stmt)
            # this assumes there is only one result returned, but we use the for loop
            # here because standard list (len, [idx]) operators don't work with
            # the neo4j record list object
            count = 0
            group_uuid = None
            for record in records:
                count = count + 1
                group_uuid = record.get('group_uuid', None)
                if group_uuid is None:
                    return Response(f"Unable to process submit.  group_uuid not found on entity:{uuid}", 400)
            if count == 0:
                return Response(f"Dataset with uuid:{uuid} not found.", 404)

        user_info = auth_helper.getUserInfo(token, getGroups=True)
        if isinstance(user_info, Response):
            return user_info
        if not 'hmgroupids' in user_info:
            return Response("user not authorized to submit data, unable to retrieve any group information", 403)
        if not data_admin_group_uuid in user_info['hmgroupids']:
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
                                headers={'Authorization': 'Bearer ' + token, 'X-Hubmap-Application': 'ingest-api'},
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
            r = requests.post(pipeline_url, json={"submission_id": "{uuid}".format(uuid=uuid),
                                                  "process": current_app.config['INGEST_PIPELINE_DEFAULT_PROCESS'],
                                                  "full_path": ingest_helper.get_dataset_directory_absolute_path(
                                                      dataset_request, group_uuid, uuid),
                                                  "provider": "{group_name}".format(
                                                      group_name=AuthHelper.getGroupDisplayName(group_uuid))},
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
                                    headers={'Authorization': 'Bearer ' + token, 'X-Hubmap-Application': 'ingest-api'},
                                    verify=False)
            if not response.status_code == 200:
                error_msg = f"call to {put_url} failed with code:{response.status_code} message:" + response.text
                logger.error(error_msg)
        except HTTPException as hte:
            logger.error(hte)
        except Exception as e:
            logger.error(e, exc_info=True)

    thread = Thread(target=call_airflow)
    thread.start()
    return Response("Request of Dataset Submisssion Accepted", 202)
