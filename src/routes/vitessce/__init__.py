import logging
from uuid import UUID

from flask import Blueprint, Response, current_app, jsonify, request
from hubmap_commons.hm_auth import AuthHelper
from hubmap_sdk import EntitySdk
from hubmap_sdk.sdk_helper import HTTPException
from hubmap_sdk.sdk_helper import HTTPException as SDKException
from portal_visualization.builder_factory import get_view_config_builder
from werkzeug.exceptions import HTTPException as WerkzeugException

from lib.decorators import suppress_print
from lib.exceptions import ResponseException
from lib.rule_chain import (
    NoMatchException,
    RuleLogicException,
    RuleSyntaxException,
    get_assay_info,
)
from lib.vitessce import VitessceConfigCache

vitessce_blueprint = Blueprint("vitessce", __name__)
logger = logging.getLogger(__name__)


@vitessce_blueprint.route("/vitessce/<string:ds_uuid>", methods=["GET"])
def get_vitessce_config(ds_uuid: str):
    try:
        UUID(ds_uuid)
    except Exception:
        return jsonify({"error": "uuid must be a valid UUID"}), 400

    try:
        auth_helper_instance = AuthHelper.instance()
        groups_token = auth_helper_instance.getAuthorizationTokens(request.headers)
        if not isinstance(groups_token, str):
            return jsonify({"error": "unauthorized"}), 401

        cache: VitessceConfigCache = current_app.vitessce_cache
        if cache and (config := cache.get(ds_uuid, groups_token, as_str=True)):
            return Response(config, 200, mimetype="application/json")

        # Get entity from entity-api
        entity_api_url = current_app.config["ENTITY_WEBSERVICE_URL"]
        entity_api = EntitySdk(token=groups_token, service_url=entity_api_url)
        entity = entity_api.get_entity_by_id(ds_uuid)
        entity = vars(entity)  # config builder expects dict

        # RNASeqAnnDataZarrViewConfBuilder expects 'metadata' in the entity
        entity["metadata"] = entity.get("ingest_metadata", {})
        # config builder expects 'files' in the entity, not in the entity 'ingest_metadata'
        entity["files"] = entity.get("metadata").get("files", [])

        # Get assaytype from soft-assay
        BuilderCls = get_view_config_builder(entity, get_assay_info)
        builder = BuilderCls(
            entity, groups_token, current_app.config["ASSETS_WEBSERVICE_URL"]
        )
        with suppress_print():
            # prevent the config from being logged
            vitessce_conf = builder.get_conf_cells(marker=None)

        if len(vitessce_conf) < 1 or not vitessce_conf[0]:
            raise ValueError("empty vitessce config")

        config = vitessce_conf[0]
        if cache:
            cache.set(entity["uuid"], config, groups_token)
        return jsonify(config), 200

    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except NoMatchException:
        return {}
    except (RuleSyntaxException, RuleLogicException) as excp:
        return Response(f"Error applying classification rules: {excp}", 500)
    except WerkzeugException as excp:
        return excp
    except (HTTPException, SDKException) as hte:
        return Response(
            f"Error while getting assay type for {ds_uuid}: " + hte.get_description(),
            hte.get_status_code(),
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            f"Unexpected error while retrieving entity {ds_uuid}: " + str(e), 500
        )


@vitessce_blueprint.route("/vitessce/<string:ds_uuid>/cache", methods=["DELETE"])
def flush_cache(ds_uuid: str):
    try:
        UUID(ds_uuid)
    except Exception:
        return jsonify({"error": "uuid must be a valid UUID"}), 400

    cache: VitessceConfigCache = current_app.vitessce_cache
    if cache:
        auth_helper_instance = AuthHelper.instance()
        groups_token = auth_helper_instance.getAuthorizationTokens(request.headers)
        if not isinstance(groups_token, str):
            return jsonify({"error": "unauthorized"}), 401

        if not cache.get(ds_uuid, groups_token):
            msg = f"The cached data does not exist for entity {ds_uuid}"
            return jsonify({"error": msg}), 404

        deleted = cache.delete(ds_uuid)
        if deleted:
            msg = f"The cached data was deleted for entity {ds_uuid}"
        else:
            msg = f"The cached data was not deleted for entity {ds_uuid}"
    else:
        msg = "The cached data was not deleted because caching is not enabled"

    return jsonify({"message": msg}), 200
