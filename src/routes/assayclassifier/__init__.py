import logging
import urllib

from atlas_consortia_commons.decorator import require_json, require_valid_token
from flask import Blueprint, Response, jsonify
from hubmap_commons.exceptions import HTTPException
from werkzeug.exceptions import HTTPException as WerkzeugException

from lib.exceptions import ResponseException
from lib.rule_chain import (
    NoMatchException,
    RuleLogicException,
    RuleSyntaxException,
    build_entity_metadata,
    calculate_assay_info,
    initialize_rule_chains,
    get_data_from_ubkg
)
from lib.services import get_entity, get_token

from .source_is_human import source_is_human

assayclassifier_blueprint = Blueprint("assayclassifier", __name__)

logger: logging.Logger = logging.getLogger(__name__)


@assayclassifier_blueprint.route("/assaytype/<ds_uuid>", methods=["GET"])
def get_ds_assaytype(ds_uuid: str):
    try:
        token = get_token()
        entity = get_entity(ds_uuid, token, True)
        metadata = build_entity_metadata(entity)
        is_human = source_is_human(
            [ds_uuid],
            token,
        )
        rules_json = calculate_assay_info(
            metadata,
            is_human,
            get_data_from_ubkg,
        )
        return jsonify(rules_json)
    except ValueError as excp:
        logger.error(excp, exc_info=True)
        return Response(f"Bad parameter: {excp}", 400)
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except NoMatchException as excp:
        logger.error(excp, exc_info=True)
        return {}
    except (RuleSyntaxException, RuleLogicException) as excp:
        logger.error(excp, exc_info=True)
        return Response(f"Error applying classification rules: {excp}", 500)
    except WerkzeugException as excp:
        logger.error(excp, exc_info=True)
        return excp
    except HTTPException as hte:
        logger.error(hte, exc_info=True)
        return Response(
            f"Error while getting assay type for {ds_uuid}: {hte.get_description()}",
            hte.get_status_code(),
        )
    except urllib.error.HTTPError as hte:
        logger.error(hte, exc_info=True)
        return Response(
            f"Error while getting assay type for {ds_uuid}: {hte}",
            hte.status,
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            f"Unexpected error while retrieving entity {ds_uuid}: " + str(e),
            500,
        )


@assayclassifier_blueprint.route("/assaytype/metadata/<ds_uuid>", methods=["GET"])
def get_ds_rule_metadata(ds_uuid: str):
    try:
        token = get_token()
        entity = get_entity(ds_uuid, token, True)
        if entity == {}:
            return Response(f"Entity with uuid {ds_uuid} not found", 404)
        metadata = build_entity_metadata(entity)
        return jsonify(metadata)
    except ValueError as excp:
        logger.error(excp, exc_info=True)
        return Response(f"Bad parameter: {excp}", 400)
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except NoMatchException as excp:
        logger.error(excp, exc_info=True)
        return {}
    except (RuleSyntaxException, RuleLogicException) as excp:
        logger.error(excp, exc_info=True)
        return Response(f"Error applying classification rules: {excp}", 500)
    except WerkzeugException as excp:
        logger.error(excp, exc_info=True)
        return excp
    except HTTPException as hte:
        logger.error(hte, exc_info=True)
        return Response(
            f"Error while getting assay type for {ds_uuid}: {hte.get_description()}",
            hte.get_status_code(),
        )
    except urllib.error.HTTPError as hte:
        logger.error(hte, exc_info=True)
        return Response(
            f"Error while getting assay type for {ds_uuid}: {hte}",
            hte.status,
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            f"Unexpected error while retrieving entity {ds_uuid}: {e}",
            500,
        )


@assayclassifier_blueprint.route("/assaytype", methods=["POST"])
@require_json(param="metadata")
def get_assaytype_from_metadata(metadata: dict):
    try:
        token = get_token()
        if parent_sample_ids := metadata.get("parent_sample_id"):
            is_human = source_is_human(parent_sample_ids.split(","), token)
        else:
            is_human = True  # default to human for safety
        rules_json = calculate_assay_info(metadata, is_human, get_data_from_ubkg)
        return jsonify(rules_json)
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except NoMatchException as excp:
        logger.error(excp, exc_info=True)
        return {}
    except (RuleSyntaxException, RuleLogicException) as excp:
        logger.error(excp, exc_info=True)
        return Response(f"Error applying classification rules: {excp}", 500)
    except WerkzeugException as excp:
        logger.error(excp, exc_info=True)
        return excp
    except HTTPException as hte:
        logger.error(hte, exc_info=True)
        return Response(
            f"Error while getting assay type from metadata: {hte.get_description()}",
            hte.get_status_code(),
        )
    except urllib.error.HTTPError as hte:
        logger.error(hte, exc_info=True)
        return Response(
            f"Error while getting assay type from metadata: {hte}",
            hte.status,
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(
            f"Unexpected error while getting assay type from metadata: {e}",
            500,
        )


@assayclassifier_blueprint.route("/reload-assaytypes", methods=["PUT"])
def reload_chain():
    try:
        initialize_rule_chains()
        return jsonify({})
    except ResponseException as re:
        logger.error(re, exc_info=True)
        return re.response
    except (RuleSyntaxException, RuleLogicException) as excp:
        logger.error(excp, exc_info=True)
        return Response(f"Error applying classification rules: {excp}", 500)
    except HTTPException as hte:
        logger.error(hte, exc_info=True)
        return Response(
            f"Error while getting assay types: {hte.get_description()}",
            hte.get_status_code(),
        )
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response(f"Unexpected error while reloading rule chain: {e}", 500)
