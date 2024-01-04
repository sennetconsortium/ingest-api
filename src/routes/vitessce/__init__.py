import logging

from flask import Blueprint, Response, current_app, jsonify, request
from hubmap_commons.hm_auth import AuthHelper
from portal_visualization.builder_factory import get_view_config_builder

from lib.decorators import require_json
from lib.rule_chain import calculate_assay_info

vitessce_blueprint = Blueprint("vitessce", __name__)
logger = logging.getLogger(__name__)


@vitessce_blueprint.route("/vitessce/config", methods=["POST"])
@require_json(param="entity")
def vitessce_config(entity: dict):
    def get_assaytype(entity):
        if "metadata" in entity.get("metadata", {}):
            metadata = entity["metadata"]["metadata"]
        else:
            metadata = {
                "entity_type": entity.get("entity_type"),
                "data_types": entity.get("data_types"),
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
        return jsonify(vitessce_conf[0] or {}), 200
    except Exception as e:
        logger.error(e)
        return Response("Unexpected error while retrieving Vitessce config", 500)
