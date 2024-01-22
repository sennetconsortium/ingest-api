import logging

from flask import Blueprint, Response, current_app, jsonify, request
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.hm_auth import AuthHelper
from hubmap_sdk import EntitySdk
from hubmap_sdk.sdk_helper import HTTPException as SDKException
from werkzeug.exceptions import HTTPException as WerkzeugException

from lib.decorators import require_json
from lib.exceptions import ResponseException
from lib.rule_chain import (
    NoMatchException,
    RuleLogicException,
    RuleSyntaxException,
    calculate_assay_info,
    get_assay_info,
    initialize_rule_chain,
)

assayclassifier_blueprint = Blueprint("assayclassifier", __name__)

logger: logging.Logger = logging.getLogger(__name__)


@assayclassifier_blueprint.route("/assaytype/<ds_uuid>", methods=["GET"])
def get_ds_assaytype(ds_uuid: str):
    try:
        auth_helper_instance = AuthHelper.instance()
        groups_token = auth_helper_instance.getAuthorizationTokens(request.headers)
        if not isinstance(groups_token, str):
            groups_token = None
        entity_api_url = current_app.config["ENTITY_WEBSERVICE_URL"]
        entity_api = EntitySdk(token=groups_token, service_url=entity_api_url)
        entity = entity_api.get_entity_by_id(ds_uuid)
        assay_info = get_assay_info(entity)
        return jsonify(assay_info)
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


@assayclassifier_blueprint.route("/assaytype", methods=["POST"])
@require_json(param="metadata")
def get_assaytype_from_metadata(metadata: dict):
    try:
        return jsonify(calculate_assay_info(metadata))
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
            "Error while getting assay type from metadata: " + hte.get_description(),
            hte.get_status_code(),
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            "Unexpected error while getting assay type from metadata: " + str(e), 500
        )


@assayclassifier_blueprint.route("/reload-assaytypes", methods=["PUT"])
def reload_chain():
    try:
        initialize_rule_chain()
        return jsonify({})
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except (RuleSyntaxException, RuleLogicException) as excp:
        return Response(f"Error applying classification rules: {excp}", 500)
    except (HTTPException, SDKException) as hte:
        return Response(
            "Error while getting assay types: " + hte.get_description(),
            hte.get_status_code(),
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while reloading rule chain: " + str(e), 500)
