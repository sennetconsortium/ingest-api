import json
import os

from flask import jsonify, request, Response, current_app
import logging
import requests

from hubmap_commons import neo4j_driver
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons import string_helper

# Local modules
from routes.entity_CRUD.ingest_file_helper import IngestFileHelper


class DatasetHelper:

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
