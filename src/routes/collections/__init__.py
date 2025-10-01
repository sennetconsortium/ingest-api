import json
import logging

import requests
from atlas_consortia_commons.rest import abort_forbidden, abort_not_found
from flask import Blueprint, Response, current_app, jsonify, request
from hubmap_commons import file_helper as commons_file_helper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.hm_auth import AuthHelper
from hubmap_sdk import EntitySdk

from lib.datacite_api import DataciteApiException
from lib.datacite_doi_helper import DataCiteDoiHelper
from lib.neo4j_helper import Neo4jHelper
from lib.services import get_entity_by_id

collections_blueprint = Blueprint("collections", __name__)
logger = logging.getLogger(__name__)

"""
Takes a valid id for a collection entity, validates that it contains required fields and has datasets in the published state,
then registers a DOI, updates the collection via entity-api, and returns the new registered_doi
"""


@collections_blueprint.route("/collections/<collection_id>/register-doi", methods=["PUT"])
def register_collections_doi(collection_id):
    try:
        auth_helper = AuthHelper.configured_instance(
            current_app.config["APP_CLIENT_ID"], current_app.config["APP_CLIENT_SECRET"]
        )
        user_info = auth_helper.getUserInfoUsingRequest(request, getGroups=True)
        if user_info is None:
            return jsonify({"error": "Unable to obtain user information for auth token"}), 401
        if isinstance(user_info, Response):
            return user_info
        if "hmgroupids" not in user_info:
            abort_forbidden("User has no valid group information to authorize publication.")
        if not auth_helper.has_data_admin_privs(
            auth_helper.getUserTokenFromRequest(request, getGroups=True)
        ):
            abort_forbidden("User must be a member of the SenNet Data Admin group to publish data.")
        if collection_id is None or len(collection_id) == 0:
            return (
                jsonify({"error": "identifier parameter is required to publish a collection."}),
                400,
            )
        r = requests.get(
            commons_file_helper.ensureTrailingSlashURL(current_app.config["UUID_WEBSERVICE_URL"])
            + "uuid/"
            + collection_id,
            headers={"Authorization": request.headers["AUTHORIZATION"]},
        )
        if r.ok is False:
            return jsonify({"error": f"{r.text}"}), r.status_code
        collection_uuid = json.loads(r.text)["uuid"]
        if json.loads(r.text).get("type").lower() not in ["collection", "epicollection"]:
            return jsonify({"error": f"{collection_uuid} is not a collection"}), 400

        # Sources/Samples need to have `data_access_level` of "public", Dataset needs a status of "Published"
        with Neo4jHelper.get_instance().session() as session:
            q = (
                "MATCH (collection:Collection {uuid: $uuid})<-[:IN_COLLECTION]-(entity:Entity) "
                "RETURN distinct entity.uuid AS uuid, entity.data_access_level as data_access_level, entity.entity_type as entity_type, entity.status AS status"
            )
            rval = session.run(q, uuid=collection_uuid).data()
            unpublished_entities = []
            for node in rval:
                uuid = node["uuid"]
                if node["entity_type"] == "Dataset":
                    if node["status"].lower() != "published":
                        unpublished_entities.append(uuid)
                elif node["entity_type"] in ["Sample", "Source"]:
                    if node["data_access_level"].lower() != "public":
                        unpublished_entities.append(uuid)

            if len(unpublished_entities) > 0:
                return (
                    jsonify(
                        {
                            "error": f"Collection with uuid {collection_uuid} has one more associated entities that have not been Published.",
                            "entity_uuids": ", ".join(unpublished_entities),
                        }
                    ),
                    422,
                )

            # get info for the collection to be published
            q = "MATCH (e:Collection {uuid: $uuid}) RETURN e.uuid as uuid, e.contacts as contacts, e.contributors as contributors"
            rval = session.run(q, uuid=collection_uuid).data()
            collection_contacts = rval[0]["contacts"]
            collection_contributors = rval[0]["contributors"]
            if collection_contributors is None or collection_contacts is None:
                return (
                    jsonify(
                        {
                            "error": "Collection missing contacts or contributors field. Must have at least one of each"
                        }
                    ),
                    400,
                )

            if len(collection_contributors) < 1 or len(collection_contacts) < 1:
                return (
                    jsonify(
                        {
                            "error": "Collection missing contacts or contributors. Must have at least one of each"
                        }
                    ),
                    400,
                )

            auth_tokens = auth_helper.getAuthorizationTokens(request.headers)
            entity_instance = EntitySdk(
                token=auth_tokens, service_url=current_app.config["ENTITY_WEBSERVICE_URL"]
            )

            doi_info = None

            entity = get_entity_by_id(collection_uuid, token=auth_tokens)
            if entity == {}:
                abort_not_found(f"Entity with uuid {collection_uuid} not found")

            entity_dict = vars(entity)
            datacite_doi_helper = DataCiteDoiHelper()
            # Checks both whether a doi already exists, as well as if it is already findable. If True, DOI exists and is findable
            # If false, DOI exists but is not yet in findable. If None, doi does not yet exist.
            try:
                doi_exists = datacite_doi_helper.check_doi_existence_and_state(entity_dict)
            except DataciteApiException as e:
                logger.exception(f"Exception while fetching doi for {collection_uuid}")
                return (
                    jsonify(
                        {
                            "error": f"Error occurred while trying to confirm existence of doi for {collection_uuid}. {e}"
                        }
                    ),
                    500,
                )
            # Doi does not exist, create draft then make it findable
            if doi_exists is None:
                try:
                    datacite_doi_helper.create_collection_draft_doi(entity_dict)
                except DataciteApiException as datacite_exception:
                    return (
                        jsonify({"error": str(datacite_exception)}),
                        datacite_exception.error_code,
                    )
                except Exception:
                    logger.exception(f"Exception while creating a draft doi for {collection_uuid}")
                    return (
                        jsonify(
                            {
                                "error": f"Error occurred while trying to create a draft doi for {collection_uuid}. Check logs."
                            }
                        ),
                        500,
                    )
                # This will make the draft DOI created above 'findable'....
                try:
                    doi_info = datacite_doi_helper.move_doi_state_from_draft_to_findable(
                        entity_dict, auth_tokens
                    )
                except Exception:
                    logger.exception(
                        f"Exception while creating making doi findable and saving to entity for {collection_uuid}"
                    )
                    return (
                        jsonify(
                            {
                                "error": f"Error occurred while making doi findable and saving to entity for {collection_uuid}. Check logs."
                            }
                        ),
                        500,
                    )
            # Doi exists, but is not yet findable. Just make it findable
            elif doi_exists is False:
                try:
                    doi_info = datacite_doi_helper.move_doi_state_from_draft_to_findable(
                        entity_dict, auth_tokens
                    )
                except Exception:
                    logger.exception(
                        f"Exception while creating making doi findable and saving to entity for {collection_uuid}"
                    )
                    return (
                        jsonify(
                            {
                                "error": f"Error occurred while making doi findable and saving to entity for {collection_uuid}. Check logs."
                            }
                        ),
                        500,
                    )
            # The doi exists and it is already findable, skip both steps
            elif doi_exists is True:
                logger.debug(
                    f"DOI for {collection_uuid} is already findable. Skipping creation and state change."
                )
                doi_name = datacite_doi_helper.build_doi_name(entity_dict)
                doi_info = {"registered_doi": doi_name, "doi_url": f"https://doi.org/{doi_name}"}
            doi_update_data = ""
            if doi_info is not None:
                doi_update_data = {
                    "registered_doi": doi_info["registered_doi"],
                    "doi_url": doi_info["doi_url"],
                }

            entity_instance.clear_cache(collection_uuid)
            entity_instance.update_entity(collection_uuid, doi_update_data)

        return jsonify({"registered_doi": f"{doi_info['registered_doi']}"})

    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return (
            jsonify(
                {
                    "error": "Unexpected error while registering collection doi: "
                    + str(e)
                    + "  Check the logs"
                }
            ),
            500,
        )
