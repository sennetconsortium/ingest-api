import logging
from uuid import UUID

from flask import Blueprint, current_app, jsonify, request
from hubmap_commons.hm_auth import AuthHelper
from portal_visualization.builder_factory import get_view_config_builder

from lib.decorators import require_json
from lib.rule_chain import calculate_assay_info

vitessce_blueprint = Blueprint("vitessce", __name__)
logger = logging.getLogger(__name__)


@vitessce_blueprint.route("/vitessce/config", methods=["POST"])
@require_json(param="entity")
def vitessce_config(entity: dict):
    if errors := validate_vitessce_entity(entity) :
        return jsonify({"error": errors}), 400

    def get_assaytype(entity):
        if "metadata" in entity.get("metadata", {}):
            metadata = entity["metadata"]["metadata"]
        else:
            if "data_types" in entity and entity.get("data_types"):
                metadata = {
                    "entity_type": entity.get("entity_type"),
                    "data_types": entity.get("data_types"),
                }
            else:
                metadata = {
                    "entity_type": entity.get("entity_type"),
                    "data_types": [entity.get("dataset_type")],
                }
        return calculate_assay_info(metadata)

    try:
        auth_helper_instance = AuthHelper.instance()
        groups_token = auth_helper_instance.getAuthorizationTokens(request.headers)
        BuilderCls = get_view_config_builder(entity, get_assaytype)
        builder = BuilderCls(
            entity, groups_token, current_app.config["ASSETS_WEBSERVICE_URL"]
        )
        vitessce_conf = builder.get_conf_cells(marker=None)
        if len(vitessce_conf) < 1 or not vitessce_conf[0]:
            raise ValueError("empty vitessce config")
        return jsonify(vitessce_conf[0]), 200
    except Exception as e:
        logger.error(f"Error while retrieving Vitessce config for uuid {entity['uuid']}:", e)
        return jsonify({"error": "404 Not Found: Entity or filepath not found"}), 404


def validate_vitessce_entity(entity):
    """Add basic validation for vitessce config request body

    Args:
        entity (dict): vitessce config request body

    Returns:
        list: list of errors
    """
    errors = []
    try:
        UUID(entity.get("uuid"))
    except Exception:
        errors.append("uuid must be a valid UUID")

    if not entity.get("status") or not isinstance(entity["status"], str):
        errors.append("'status' string is required")

    if not entity.get("data_types") or not isinstance(entity["data_types"], list):
        errors.append("'data_types' array is required")

    if not entity.get("files") or not isinstance(entity["files"], list):
        errors.append("'files' array is required")

    if entity.get("entity_type") != "Dataset":
        errors.append("'entity_type' 'Dataset' is required")

    prov_list = entity.get("metadata", {}).get("dag_provenance_list")
    if not prov_list or not isinstance(prov_list, list):
        errors.append("'metadata.dag_provenance_list' array is required")

    return errors
