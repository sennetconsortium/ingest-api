import logging
import os
import time
from uuid import UUID

from atlas_consortia_commons.rest import (
    abort_bad_req,
    abort_not_found,
    abort_unauthorized,
)
from atlas_consortia_commons.string import equals
from flask import Blueprint, current_app, jsonify, request
from globus_sdk import (
    AccessTokenAuthorizer,
    ConfidentialAppAuthClient,
    TransferClient,
    TransferData,
)
from hubmap_commons.hm_auth import AuthHelper

from lib.ingest_file_helper import IngestFileHelper
from lib.ontology import Ontology
from lib.services import get_entity

transfers_blueprint = Blueprint("transfers", __name__)
logger = logging.getLogger(__name__)


@transfers_blueprint.route("/transfers/endpoints", methods=["GET"])
def get_user_transfer_endpoints():
    auth_helper = AuthHelper.configured_instance(
        current_app.config["APP_CLIENT_ID"],
        current_app.config["APP_CLIENT_SECRET"],
    )

    token = auth_helper.getUserTokenFromRequest(request, getGroups=True)
    if not isinstance(token, str):
        print("Token is not a string")
        abort_unauthorized("User must be a member of the SenNet Consortium")

    if not is_active_transfer_token(token):
        print("Token is not a transfer token")
        abort_unauthorized("User must present a valid Globus Transfer token")

    authorizer = AccessTokenAuthorizer(token)
    tc = TransferClient(authorizer=authorizer)
    try:
        search_result = tc.endpoint_search(filter_scope="my-endpoints")
    except Exception as e:
        logger.error(f"Error retrieving transfer endpoints: {e}")
        abort_unauthorized("User must present a valid Globus Transfer token")

    endpoints = [
        {
            "id": ep["id"],
            "display_name": ep["display_name"],
        }
        for ep in search_result
    ]

    return jsonify(endpoints), 200


@transfers_blueprint.route("/transfers", methods=["POST"])
def initiate_transfer():
    auth_helper = AuthHelper.configured_instance(
        current_app.config["APP_CLIENT_ID"],
        current_app.config["APP_CLIENT_SECRET"],
    )

    # Validate user transfer token
    token = auth_helper.getUserTokenFromRequest(request, getGroups=True)
    if not isinstance(token, str):
        print("Token is not a string")
        abort_unauthorized("User must be a member of the SenNet Consortium")

    if not is_active_transfer_token(token):
        print("Token is not a transfer token")
        abort_unauthorized("User must present a valid Globus Transfer token")

    # Validate request payload
    data = request.get_json()
    if not data:
        abort_bad_req("Invalid request payload")

    dest_ep_id = data.get("destination_collection_id")
    base_dest_path = data.get("destination_file_path", "/sennet-data")
    from_protected_space = data.get("from_protected_space", False)
    manifest = data.get("manifest")

    # Basic validation of required fields
    if not dest_ep_id:
        abort_bad_req("Destination collection ID is required")
    try:
        UUID(dest_ep_id)
    except (ValueError, TypeError):
        abort_bad_req("Destination collection ID must be a valid UUID")

    if not manifest:
        abort_bad_req("Manifest is required")

    # Check user has access to destination endpoint
    authorizer = AccessTokenAuthorizer(token)
    tc = TransferClient(authorizer=authorizer)
    ingest_helper = IngestFileHelper(current_app.config)

    transfer_data_map = dict[str, TransferData]()  # globus_endpoint_uuid -> TransferData
    for item in manifest:
        ent_uuid = item.get("dataset")
        if not ent_uuid:
            abort_bad_req("Each manifest item must include a dataset UUID")

        try:
            ent = get_entity(
                entity_id=ent_uuid,
                token=auth_helper.getProcessSecret(),
                as_dict=True,
            )
            if not equals(ent["entity_type"], Ontology.ops().entities().DATASET):
                abort_bad_req(f"Entity is not a Dataset: {ent_uuid}")
        except Exception as e:
            print("Error retrieving entity:", e)
            abort_not_found(f"Failed to find entity: {ent_uuid}")

        dataset = ent

        # returns {"rel_path": rel_path, "globus_endpoint_uuid": endpoint_id}
        path = ingest_helper.get_dataset_directory_relative_path(
            dataset_record=dataset,
            group_uuid=dataset["group_uuid"],
            dataset_uuid=dataset["uuid"],
            return_protected=from_protected_space,
        )

        src_ep_ip = path["globus_endpoint_uuid"]
        if src_ep_ip not in transfer_data_map:
            transfer_data_map[src_ep_ip] = TransferData(
                transfer_client=tc,
                source_endpoint=src_ep_ip,
                destination_endpoint=dest_ep_id,
                verify_checksum=True,
                encrypt_data=True,
            )

        # Determine paths for source and destination
        file_path = os.path.normpath(item["file_path"]).lstrip("/")

        # Assume file if extension exists, directory otherwise
        _, ext = os.path.splitext(file_path)
        if ext:
            recursive = False
        else:
            recursive = True

        src_path = os.path.join(path["rel_path"], file_path)
        dst_path = os.path.join(base_dest_path, f"{ent["sennet_id"]}-{ent_uuid}", file_path)

        transfer_data_map[src_ep_ip].add_item(src_path, dst_path, recursive=recursive)

    try:
        # try to auto-activate endpoints for the user (harmless if already active)
        tc.endpoint_autoactivate(dest_ep_id)
    except Exception:
        logger.debug("autoactivate failed for endpoint %s", dest_ep_id)

    try:
        task_ids = []

        # This order ensures unauthorized transfers are caught early
        # submit protected/consortium transfer, if any
        td = transfer_data_map.get(current_app.config["GLOBUS_PROTECTED_ENDPOINT_UUID"])
        if td and td.keys():
            result = tc.submit_transfer(td)
            task_ids.append(result["task_id"])

        # submit public transfer, if any
        td = transfer_data_map.get(current_app.config["GLOBUS_PUBLIC_ENDPOINT_UUID"])
        if td and td.keys():
            result = tc.submit_transfer(td)
            task_ids.append(result["task_id"])

        return jsonify({"task_ids": task_ids}), 202

    except Exception as e:
        logger.error("Transfer submission failed: %s", e)
        abort_unauthorized("Transfer submission failed")


def is_active_transfer_token(token: str) -> bool:
    """Check if the provided token is an active Globus Transfer token.

    Parameters
    ----------
    token : str
        The token to check.

    Returns
    -------
    bool
        True if the token is an active transfer token, False otherwise.
    """
    ac = ConfidentialAppAuthClient(
        current_app.config["APP_CLIENT_ID"],
        current_app.config["APP_CLIENT_SECRET"],
    )
    try:
        info = ac.oauth2_token_introspect(token)
        issued = info.get("iat", 0)
        # get utc time difference btween now and issued time in minutes
        now = int(time.time())
        diff_minutes = (now - issued) / 60
        logger.info(
            f"token info - Active: {info.get('active')}, Issued: {issued}, "
            f"Age (minutes): {diff_minutes}"
        )
    except Exception as e:
        logger.debug("token introspect failed: %s", e)
        return False
    if not info.get("active"):
        return False
    aud = info.get("aud", [])
    return any(a == "transfer.api.globus.org" in a for a in aud)
