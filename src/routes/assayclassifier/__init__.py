import logging
from typing import Optional

from atlas_consortia_commons.decorator import require_json, require_valid_token, User
from flask import Blueprint, Response, jsonify, request
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.hm_auth import AuthHelper
from hubmap_sdk.sdk_helper import HTTPException as SDKException
from werkzeug.exceptions import HTTPException as WerkzeugException

from lib.exceptions import ResponseException
from lib.rule_chain import (
    NoMatchException,
    RuleLogicException,
    RuleSyntaxException,
    build_entity_metadata,
    calculate_assay_info,
    initialize_rule_chain,
)
from lib.services import get_entity, get_token

assayclassifier_blueprint = Blueprint("assayclassifier", __name__)

logger: logging.Logger = logging.getLogger(__name__)


@assayclassifier_blueprint.route("/assaytype/<ds_uuid>", methods=["GET"])
def get_ds_assaytype(ds_uuid: str):
    try:
        token = get_token()
        entity = get_entity(ds_uuid, token)
        metadata = build_entity_metadata(entity)
        rule_value_set = calculate_assay_info(metadata)

        if sources := entity.sources:
            source_type = ""
            for source in sources:
                if source_type := source.get("source_type"):
                    # If there is a single Human source_type, treat this as a Human case
                    if source_type.upper() == "HUMAN":
                        break
            apply_source_type_transformations(source_type, rule_value_set)

        return jsonify(rule_value_set)
    except ValueError as excp:
        logger.error(excp, exc_info=True)
        return Response("Bad parameter: {excp}", 400)
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


@assayclassifier_blueprint.route("/assaytype/metadata/<ds_uuid>", methods=["GET"])
def get_ds_rule_metadata(ds_uuid: str):
    try:
        token = get_token()
        entity = get_entity(ds_uuid, token)
        metadata = build_entity_metadata(entity)
        return jsonify(metadata)
    except ValueError as excp:
        logger.error(excp, exc_info=True)
        return Response("Bad parameter: {excp}", 400)
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


def apply_source_type_transformations(source_type: str, rule_value_set: dict) -> dict:
    # If we get more complicated transformations we should consider refactoring.
    # For now, this should suffice.
    if "MOUSE" in source_type.upper():
        rule_value_set["contains-pii"] = False

    return rule_value_set


@assayclassifier_blueprint.route("/assaytype", methods=["POST"])
@require_valid_token()
@require_json(param="metadata")
def get_assaytype_from_metadata(token: str, user: User, metadata: dict):
    try:
        rule_value_set = calculate_assay_info(metadata)

        if parent_sample_ids := metadata.get("parent_sample_id"):
            source_type = ""
            parent_sample_ids = parent_sample_ids.split(",")
            for parent_sample_id in parent_sample_ids:
                parent_entity = get_entity(parent_sample_id, token)
                if source_type := parent_entity.source.get("source_type"):
                    # If there is a single Human source_type, treat this as a Human case
                    if source_type.upper() == "HUMAN":
                        break

            apply_source_type_transformations(source_type, rule_value_set)
        return jsonify(rule_value_set)
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

