import logging

from flask import Blueprint, Response, current_app, jsonify, request
from hubmap_commons.hm_auth import AuthHelper
from hubmap_sdk.sdk_helper import HTTPException
from hubmap_sdk.sdk_helper import HTTPException as SDKException
from portal_visualization.builder_factory import get_view_config_builder
from werkzeug.exceptions import HTTPException as WerkzeugException

from lib import suppress_print
from lib.exceptions import ResponseException
from lib.rule_chain import (
    NoMatchException,
    RuleLogicException,
    RuleSyntaxException,
    build_entity_metadata,
    calculate_assay_info,
)
from lib.services import get_entity
from lib.vitessce import VitessceConfigCache, strip_extras

vitessce_blueprint = Blueprint("vitessce", __name__)
logger = logging.getLogger(__name__)


@vitessce_blueprint.route("/vitessce/<entity_uuid:ds_uuid>", methods=["GET"])
def get_vitessce_config(ds_uuid: str):
    try:
        groups_token = None
        cache = None
        if request.headers.get('Authorization') is not None:
            auth_helper_instance = AuthHelper.instance()
            groups_token = auth_helper_instance.getAuthorizationTokens(request.headers)
            if not isinstance(groups_token, str):
                return jsonify({"error": "unauthorized"}), 401

            cache: VitessceConfigCache = current_app.vitessce_cache
            if cache and (config := cache.get(ds_uuid, groups_token, as_str=True)):
                return Response(config, 200, mimetype="application/json")

        # Get entity from search-api
        # entity = get_entity_from_search_api(ds_uuid, groups_token, as_dict=True)
        entity = get_entity(ds_uuid, groups_token, as_dict=True)
        if 'ingest_metadata' in entity and 'files' in entity['ingest_metadata']:
            entity['files'] = entity['ingest_metadata']['files']

        def get_assaytype(entity: dict) -> dict:
            # Get entity from entity-api
            entity = get_entity(entity["uuid"], groups_token, as_dict=True)
            metadata = build_entity_metadata(entity)
            return calculate_assay_info(metadata)

        parent = None
        assaytype = get_assaytype(entity)
        # Adding portal-visualization `builder_factory` vis-lifted image pyramids check to see if we want to pass the parent
        if 'is_support' in assaytype['vitessce-hints'] and 'is_image' in assaytype['vitessce-hints']:
            parent = entity['direct_ancestors'][0]
        BuilderCls = get_view_config_builder(entity, get_assaytype, parent)
        builder = BuilderCls(
            entity, groups_token, current_app.config["ASSETS_WEBSERVICE_URL"]
        )
        with suppress_print():
            # prevent the config from being logged
            vitessce_conf = builder.get_conf_cells(marker=None)

        if len(vitessce_conf) < 1 or not vitessce_conf[0]:
            raise ValueError("empty vitessce config")

        config = vitessce_conf[0]
        logger.info(f"Vitessce config: {config}")

        if cache:
            cache.set(entity["uuid"], config, groups_token)

        if groups_token is None:
            config = strip_extras(config)

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


@vitessce_blueprint.route("/vitessce/<entity_uuid:ds_uuid>/cache", methods=["DELETE"])
def flush_cache(ds_uuid: str):
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
