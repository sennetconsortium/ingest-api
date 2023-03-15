import json
import os
import sys
from pathlib import Path
from shutil import copy2

from flask import jsonify, request, Response, current_app
import logging
import requests

from hubmap_commons import neo4j_driver
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons import string_helper

# Local modules
from hubmap_commons.hubmap_const import HubmapConst
from hubmap_sdk import EntitySdk, Dataset

from lib.file_upload_helper import UploadFileHelper
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper


class DatasetHelper:
    confdata = {}

    def __init__(self, config):
        self.appconfig = config
        self.logger = logging.getLogger('ingest.service')
        self.auth_helper_instance = AuthHelper.configured_instance(config['APP_CLIENT_ID'], config['APP_CLIENT_SECRET'])
        self.ingest_helper = IngestFileHelper(config)

        # The new neo4j_driver (from commons package) is a singleton module
        # This neo4j_driver_instance will be used for application-specifc neo4j queries
        # as well as being passed to the schema_manager
        try:
            self.neo4j_driver_instance = neo4j_driver.instance(self.appconfig['NEO4J_SERVER'],
                                                               self.appconfig['NEO4J_USERNAME'],
                                                               self.appconfig['NEO4J_PASSWORD'])

            self.logger.info("Initialized neo4j_driver module successfully :)")
        except Exception:
            msg = "Failed to initialize the neo4j_driver module"
            # Log the full stack trace, prepend a line with our message
            self.logger.exception(msg)

    def get_group_uuid_by_dataset_uuid(self, uuid):
        with self.neo4j_driver_instance.session() as session:
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
            return group_uuid

    def update_ingest_status_title_thumbnail(self, app_config: object, request_json: object,
                                             request_headers: object, entity_api: EntitySdk,
                                             file_upload_helper_instance: UploadFileHelper) -> object:
        dataset_uuid = request_json['dataset_id'].strip()

        # Headers for calling entity-api via PUT to update Dataset.status
        extra_headers = {
            'Content-Type': 'application/json',
            'X-Hubmap-Application': 'ingest-api'
        }

        # updated_ds is the dict returned by ingest-pipeline, not the complete entity information
        # Note: 'dataset_id' is in request_json but not in the resulting updated_ds
        # request_json['thumbnail_file_abs_path'] is converted to updated_ds['ingest_metadata']['thumbnail_file_abs_path']
        updated_ds = self.get_dataset_ingest_update_record(request_json)

        self.logger.debug('=======get_dataset_ingest_update_record=======')
        self.logger.debug(updated_ds)

        # For thumbnail image handling if ingest-pipeline finds the file
        # and sends the absolute file path back
        try:
            thumbnail_file_abs_path = updated_ds['ingest_metadata']['thumbnail_file_abs_path']

            self.logger.debug("=======thumbnail_file_abs_path found=======")

            # Generate a temp file id and copy the source file to the temp upload dir
            temp_file_id = file_upload_helper_instance.get_temp_file_id()
            file_upload_temp_dir = file_upload_helper_instance.upload_temp_dir

            try:
                self.handle_thumbnail_file(thumbnail_file_abs_path,
                                                     entity_api,
                                                     dataset_uuid,
                                                     extra_headers,
                                                     temp_file_id,
                                                     file_upload_temp_dir)

                # Now add the thumbnail file by making a call to entity-api
                # And the entity-api will execute the trigger method defined
                # for the property 'thumbnail_file_to_add' to commit this
                # file via ingest-api's /file-commit endpoint, which treats
                # the temp file as uploaded file and moves it to the generated file_uuid
                # dir under the upload dir: /hive/hubmap/hm_uploads/<file_uuid> (for PROD)
                # and also creates the symbolic link to the assets
                updated_ds['thumbnail_file_to_add'] = {
                    'temp_file_id': temp_file_id
                }
            except requests.exceptions.RequestException as e:
                msg = e.response.text
                self.logger.exception(msg)

                # Due to the use of response.raise_for_status() in schema_manager.create_hubmap_ids()
                # we can access the status codes from the exception
                return Response(msg, e.response.status_code)
        except KeyError:
            self.logger.info(f"No existing thumbnail file found for the dataset uuid {dataset_uuid}")
            pass

        # Applying extra headers once more in case an exception occurs in handle_thumbnail_file and its is not changed
        entity_api.header.update(extra_headers)
        try:
            entity = entity_api.update_entity(dataset_uuid, updated_ds)
        except HTTPException as e:
            err_msg = f"Error while updating the dataset status using EntitySdk.update_entity() status code: {e.status_code} message: {e.description}"
            self.logger.error(err_msg)
            self.logger.error("Sent: " + json.dumps(updated_ds))
            return Response(e.description, e.status_code)

        # The PUT call returns the latest dataset...
        lastest_dataset = vars(entity)

        self.logger.debug('=======lastest_dataset before title update=======')
        self.logger.debug(lastest_dataset)

        # By this point, the response code can only be 200
        return jsonify({'result': lastest_dataset}), 200

    def handle_thumbnail_file(self, thumbnail_file_abs_path: str, entity_api: EntitySdk, dataset_uuid: str,
                              extra_headers: dict, temp_file_id: str, file_upload_temp_dir: str):
        # Delete the old thumbnail file from Neo4j before updating with new one
        # First retrieve the exisiting thumbnail file uuid
        try:
            entity = entity_api.get_entity_by_id(dataset_uuid)
        # All exceptions that occur in EntitySdk are HTTPExceptions
        except HTTPException as e:
            err_msg = f"Failed to query the dataset of uuid {dataset_uuid} while calling EntitySdk.get_entities() status code:{e.status_code}  message:{e.description}"
            self.logger.error(err_msg)
            # Bubble up the error message
            raise requests.exceptions.RequestException(err_msg)

        entity_dict = vars(entity)

        self.logger.debug('=======EntitySdk.get_entity_by_id() resulting entity_dict=======')
        self.logger.debug(entity_dict)

        # Easier to ask for forgiveness than permission (EAFP)
        # Rather than checking key existence at every level
        try:
            thumbnail_file_uuid = entity_dict['thumbnail_file']['file_uuid']

            # To remove the existing thumbnail file, just pass the file uuid as a string
            put_data = {
                'thumbnail_file_to_remove': thumbnail_file_uuid
            }
            entity_api.header.update(extra_headers)
            try:
                entity = entity_api.update_entity(dataset_uuid, put_data)
            # All exceptions that occur in EntitySdk are HTTPExceptions
            except HTTPException as e:
                err_msg = f"Failed to remove the existing thumbnail file for dataset of uuid {dataset_uuid} while calling EntitySdk.put_entities() status code:{e.status_code}  message:{e.description}"
                self.logger.error(err_msg)
                # Bubble up the error message
                raise requests.exceptions.RequestException(err_msg)

            self.logger.info(f"Successfully removed the existing thumbnail file of the dataset uuid {dataset_uuid}")
        except KeyError:
            self.logger.info(f"No existing thumbnail file found for the dataset uuid {dataset_uuid}")
            pass

        entity_dict = vars(entity)

        self.logger.debug('=======EntitySdk.update_entity() resulting entity_dict=======')
        self.logger.debug(entity_dict)

        # Create the temp file dir under the temp uploads for the thumbnail
        # /hive/hubmap/hm_uploads_tmp/<temp_file_id> (for PROD)
        temp_file_dir = os.path.join(file_upload_temp_dir, temp_file_id)

        try:
            Path(temp_file_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.exception(
                f"Failed to create the thumbnail temp upload dir {temp_file_dir} for thumbnail file attched to Dataset {dataset_uuid}")

        # Then copy the source thumbnail file to the temp file dir
        # shutil.copy2 is identical to shutil.copy() method
        # but it also try to preserves the file's metadata
        copy2(thumbnail_file_abs_path, temp_file_dir)

    def get_dataset_ingest_update_record(self, json_data):
        """ expect something like this:
        #{'dataset_id' : '4d3eb2a87cda705bde38495bb564c8dc', 'status': '<status>', 'message': 'the process ran', 'metadata': [maybe some metadata stuff], 'thumbnail_file_abs_path': 'full file path'}
        files: [{ "relativePath" : "/path/to/file/example.txt",
           "type":"filetype",
           "size":filesize,
           "checksum":"file-checksum"
         }]
         """

        if 'dataset_id' not in json_data:
            raise ValueError('cannot find dataset_id')

        # Note: `dataset_id` is not being returned!
        update_record = {}

        if 'status' not in json_data:
            raise ValueError('cannot find status')
        if json_data['status'] not in HubmapConst.DATASET_STATUS_OPTIONS:
            raise ValueError('"' + json_data['status'] + '" is not a valid status')
        update_record['status'] = json_data['status']

        # if 'files' in json_data:
        #    file_data = json_data['files']
        #    update_record[HubmapConst.DATASET_INGEST_FILE_LIST_ATTRIBUTE] = file_data
        if 'message' not in json_data:
            raise ValueError('cannot find "message" parameter')
        update_record['pipeline_message'] = json_data['message']
        update_status = update_record['status'].lower().strip()
        if update_status == 'error' or update_status == 'invalid' or update_status == 'new':
            return update_record
        metadata = None
        if not 'metadata' in json_data:
            raise ValueError('top level metadata field required')

        metadata = json_data['metadata']
        if 'files_info_alt_path' in metadata:
            metadata['files'] = self.get_file_list(metadata['files_info_alt_path'])

        if 'overwrite_metadata' in json_data and json_data['overwrite_metadata'] == False:
            raise ValueError("overwrite_metadata set to False, merging of metadata is not supported on update")

        # we can get the antibodies or contributors fields at multiple levels
        # find them and move them to the top
        antibodies = None
        contributors = None
        if 'antibodies' in json_data:
            antibodies = json_data['antibodies']
        if 'contributors' in json_data:
            contributors = json_data['contributors']

        if 'metadata' in metadata:
            meta_lvl2 = metadata['metadata']
            if 'antibodies' in meta_lvl2:
                if antibodies is None:
                    antibodies = meta_lvl2['antibodies']
                    meta_lvl2.pop('antibodies')
                else:
                    raise ValueError('antibodies array included twice in request data')
            if 'contributors' in meta_lvl2:
                if contributors is None:
                    contributors = meta_lvl2['contributors']
                    meta_lvl2.pop('contributors')
                else:
                    raise ValueError('contributors array included twice in request data')
            if 'metadata' in meta_lvl2:
                meta_lvl3 = meta_lvl2['metadata']
                if 'antibodies' in meta_lvl3:
                    if antibodies is None:
                        antibodies = meta_lvl3['antibodies']
                        meta_lvl3.pop('antibodies')
                    else:
                        raise ValueError('antibodies array included twice in request data')
                if 'contributors' in meta_lvl3:
                    if contributors is None:
                        contributors = meta_lvl3['contributors']
                        meta_lvl3.pop('contributors')
                    else:
                        raise ValueError('contributors array included twice in request data')

                # while we're here if we have that second level of metadata, move it up one level
                # but first save anything else at the same level an put it in
                # an attribute named 'extra_metadata"
                extra_meta = {}
                for key in meta_lvl2.keys():
                    if not key == 'metadata':
                        extra_meta[key] = meta_lvl2[key]
                if extra_meta:
                    metadata['extra_metadata'] = extra_meta

                metadata['metadata'] = meta_lvl3

        update_record[HubmapConst.DATASET_INGEST_METADATA_ATTRIBUTE] = metadata

        if not antibodies is None:
            update_record['antibodies'] = antibodies
        if not contributors is None:
            update_record['contributors'] = contributors
            contacts = []
            for contrib in contributors:
                if 'is_contact' in contrib:
                    v = contrib['is_contact']
                    if self.__is_true(val=v):
                        contacts.append(contrib)
            if len(contacts) > 0:
                update_record['contacts'] = contacts

        # For thumbnail image handling
        if 'thumbnail_file_abs_path' in json_data:
            update_record['thumbnail_file_abs_path'] = json_data['thumbnail_file_abs_path']

        return update_record

    def __is_true(self, val):
        if val is None: return False
        if isinstance(val, str):
            uval = val.upper().strip()
            if uval in ['TRUE', 'T', '1', 'Y', 'YES']:
                return True
            else:
                return False
        elif isinstance(val, int) and val == 1:
            return True
        else:
            return False

    def get_file_list(self, orig_file_path):
        f = None
        try:
            # join the incoming file path with the WORKFLOW_SCRATCH location
            file_path = os.path.join(self.confdata['WORKFLOW_SCRATCH'], orig_file_path)
            with open(file_path) as f:
                data = json.load(f)
                if 'files' in data:
                    return data['files']
                else:
                    raise ValueError('Cannot find the \'files\' attribute in: ' + file_path)
        except json.JSONDecodeError as jde:
            print('Cannot decode JSON in file: ' + file_path)
            raise
        except FileNotFoundError as fnfe:
            print('Cannot find file: ' + file_path)
            raise
        except PermissionError as pe:
            print('Cannot access file: ' + file_path)
            raise
        except:
            print('A general error occurred: ', sys.exc_info()[0])
            raise
        finally:
            if f != None:
                f.close()

    def determine_sources_to_reindex(self, identifier, user_info, dataset_uuid):
        is_primary = self.dataset_is_primary(dataset_uuid)
        suspend_indexing_and_acls = string_helper.isYes(request.args.get('suspend-indexing-and-acls'))
        no_indexing_and_acls = False
        if suspend_indexing_and_acls:
            no_indexing_and_acls = True

        sources_to_reindex = []
        with self.neo4j_driver_instance.session() as neo_session:
            # recds = session.run("Match () Return 1 Limit 1")
            # for recd in recds:
            #    if recd[0] == 1:
            #        is_connected = True
            #    else:
            #        is_connected = False

            # look at all of the ancestors
            # gather uuids of ancestors that need to be switched to public access_level
            # grab the id of the source ancestor to use for reindexing
            q = f"MATCH (dataset:Dataset {{uuid: '{dataset_uuid}'}})-[:WAS_GENERATED_BY]->(a1)-[:USED|WAS_GENERATED_BY*]->(all_ancestors:Entity) RETURN distinct all_ancestors.uuid as uuid, all_ancestors.entity_type as entity_type, all_ancestors.data_types as data_types, all_ancestors.data_access_level as data_access_level, all_ancestors.status as status, all_ancestors.metadata as metadata"
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
                    # TODO: Need to update logic for metadata here once we have a method in place to process it
                    # if is_primary:
                    #     if metadata is None or metadata.strip() == '':
                    #         return jsonify({"error": f"source.metadata is missing for {dataset_uuid}"}), 400
                    #     metadata = metadata.replace("'", '"')
                    #     metadata_dict = json.loads(metadata)
                    #     living_source = True
                    #     organ_source = True
                    #     if metadata_dict.get('organ_source_data') is None:
                    #         living_source = False
                    #     if metadata_dict.get('living_source_data') is None:
                    #         organ_source = False
                    #     if (organ_source and living_source) or (not organ_source and not living_source):
                    #         return jsonify({"error": f"source.metadata.organ_source_data or "
                    #                                  f"source.metadata.living_source_data required. "
                    #                                  f"Both cannot be None. Both cannot be present. Only one."}), 400
                    sources_to_reindex.append(uuid)
                    if data_access_level != 'public':
                        uuids_for_public.append(uuid)
                elif entity_type == 'Dataset':
                    if status != 'Published':
                        return Response(
                            f"{dataset_uuid} has an ancestor dataset that has not been Published. Will not Publish. Ancestor dataset is: {uuid}",
                            400)

            if has_source is False:
                return Response(f"{dataset_uuid}: no source found for dataset, will not Publish")

            # get info for the dataset to be published
            q = f"MATCH (e:Dataset {{uuid: '{dataset_uuid}'}}) RETURN e.uuid as uuid, e.entity_type as entitytype, e.status as status, e.data_access_level as data_access_level, e.group_uuid as group_uuid, e.contacts as contacts, e.contributors as contributors"
            rval = neo_session.run(q).data()
            dataset_status = rval[0]['status']
            dataset_entitytype = rval[0]['entitytype']
            dataset_data_access_level = rval[0]['data_access_level']
            dataset_group_uuid = rval[0]['group_uuid']
            dataset_contacts = rval[0]['contacts']
            dataset_contributors = rval[0]['contributors']
            if dataset_entitytype != 'Dataset':
                return Response(
                    f"{dataset_uuid} is not a dataset will not Publish, entity type is {dataset_entitytype}", 400)
            if not dataset_status == 'QA':
                return Response(f"{dataset_uuid} is not in QA state will not Publish, status is {dataset_status}", 400)

            # TODO: Re-add this code segment to check for contacts/contributors
            # if is_primary:
            #     if dataset_contacts is None or dataset_contributors is None:
            #         return jsonify({
            #             "error": f"{dataset_uuid} missing contacts or contributors. Must have at least one of each"}), 400
            #     dataset_contacts = dataset_contacts.replace("'", '"')
            #     dataset_contributors = dataset_contributors.replace("'", '"')
            #     if len(json.loads(dataset_contacts)) < 1 or len(json.loads(dataset_contributors)) < 1:
            #         return jsonify({
            #             "error": f"{dataset_uuid} missing contacts or contributors. Must have at least one of each"}), 400

            data_access_level = dataset_data_access_level
            # if consortium access level convert to public dataset, if protected access leave it protected
            if dataset_data_access_level == 'consortium':
                # before moving check to see if there is currently a link for the dataset in the assets directory
                asset_dir = self.ingest_helper.dataset_asset_directory_absolute_path(dataset_uuid)
                asset_dir_exists = os.path.exists(asset_dir)
                self.ingest_helper.move_dataset_files_for_publishing(dataset_uuid, dataset_group_uuid, 'consortium')
                uuids_for_public.append(dataset_uuid)
                data_access_level = 'public'
                if asset_dir_exists:
                    self.ingest_helper.relink_to_public(dataset_uuid)

            # acls_cmd = self.ingest_helper.set_dataset_permissions(dataset_uuid, dataset_group_uuid, data_access_level,
            #                                                       True,
            #                                                       no_indexing_and_acls)

            # TODO: Need to add DOI generation support
            # if is_primary:
            #     # DOI gets generated here
            #     # Note: moved dataset title auto generation to entity-api - Zhou 9/29/2021
            #     auth_tokens = self.auth_helper_instance.getAuthorizationTokens(request.headers)
            #     datacite_doi_helper = DataCiteDoiHelper()
            #
            #     entity_instance = EntitySdk(token=auth_tokens, service_url=current_app.config['ENTITY_WEBSERVICE_URL'])
            #     entity = entity_instance.get_entity_by_id(dataset_uuid)
            #     entity_dict = vars(entity)
            #     try:
            #         datacite_doi_helper.create_dataset_draft_doi(entity_dict, check_publication_status=False)
            #     except Exception as e:
            #         return jsonify(
            #             {"error": f"Error occurred while trying to create a draft doi for{dataset_uuid}. {e}"}), 500
            #     # This will make the draft DOI created above 'findable'....
            #     try:
            #         datacite_doi_helper.move_doi_state_from_draft_to_findable(entity_dict, auth_tokens)
            #     except Exception as e:
            #         return jsonify({
            #             "error": f"Error occurred while trying to change doi draft state to findable doi for{dataset_uuid}. {e}"}), 500

            # set dataset status to published and set the last modified user info and user who published
            update_q = "match (e:Entity {uuid:'" + dataset_uuid + "'}) set e.status = 'Published', e.last_modified_user_sub = '" + \
                       user_info['sub'] + "', e.last_modified_user_email = '" + user_info[
                           'email'] + "', e.last_modified_user_displayname = '" + user_info[
                           'name'] + "', e.last_modified_timestamp = TIMESTAMP(), e.published_timestamp = TIMESTAMP(), e.published_user_email = '" + \
                       user_info['email'] + "', e.published_user_sub = '" + user_info[
                           'sub'] + "', e.published_user_displayname = '" + user_info['name'] + "'"
            self.logger.info(dataset_uuid + "\t" + dataset_uuid + "\tNEO4J-update-base-dataset\t" + update_q)
            neo_session.run(update_q)

            # if all else worked set the list of ids to public that need to be public
            if len(uuids_for_public) > 0:
                id_list = string_helper.listToCommaSeparated(uuids_for_public, quoteChar="'")
                update_q = "match (e:Entity) where e.uuid in [" + id_list + "] set e.data_access_level = 'public'"
                self.logger.info(identifier + "\t" + dataset_uuid + "\tNEO4J-update-ancestors\t" + update_q)
                neo_session.run(update_q)

        if no_indexing_and_acls:
            # r_val = {'acl_cmd': acls_cmd, 'sources_for_indexing': sources_to_reindex}
            r_val = {'sources_for_indexing': sources_to_reindex}
        else:
            r_val = {'acl_cmd': '', 'sources_for_indexing': []}

        if not no_indexing_and_acls:
            for source_uuid in sources_to_reindex:
                try:
                    rspn = requests.put(current_app.config['SEARCH_WEBSERVICE_URL'] + "/reindex/" + source_uuid,
                                        headers={'Authorization': request.headers["AUTHORIZATION"]})
                    self.logger.info(
                        f"Publishing {identifier} indexed source {source_uuid} with status {rspn.status_code}")
                except:
                    self.logger.exception(
                        f"While publishing {identifier} Error happened when calling reindex web service for source {source_uuid}")

        return Response(json.dumps(r_val), 200, mimetype='application/json')

    # Determines if a dataset is Primary. If the list returned from the neo4j query is empty, the dataset is not primary
    def dataset_is_primary(self, dataset_uuid):
        with self.neo4j_driver_instance.session() as neo_session:
            q = (
                f"MATCH (ds:Dataset {{uuid: '{dataset_uuid}'}})-[:WAS_GENERATED_BY]->(:Activity)-[:USED]->(s:Sample) RETURN ds.uuid")
            result = neo_session.run(q).data()
            if len(result) == 0:
                return False
            return True
