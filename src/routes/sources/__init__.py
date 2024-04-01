import logging
import os
from operator import itemgetter

import requests
from atlas_consortia_commons.rest import (
    StatusCodes,
    rest_bad_req,
    rest_ok,
    rest_response,
)
from flask import Blueprint, Response, current_app, request
from hubmap_commons.file_helper import ensureTrailingSlashURL

from lib.decorators import require_valid_token
from lib.entities.validation import bulk_upload_and_validate, validate_sources
from lib.file import get_csv_records
from lib.ontology import Ontology

sources_blueprint = Blueprint("sources", __name__)
logger = logging.getLogger(__name__)


@sources_blueprint.route("/sources/bulk/validate", methods=["POST"])
@require_valid_token(param="token")
def bulk_sources_upload_and_validate(token: str):
    return bulk_upload_and_validate(Ontology.ops().entities().SOURCE, token)


@sources_blueprint.route("/sources/bulk/register", methods=["POST"])
@require_valid_token(param="token")
def create_sources_from_bulk(token: str):
    check_results = _check_request_for_bulk()
    if isinstance(check_results.get("csv_records"), Response):
        return check_results.get("csv_records")

    group_uuid = check_results.get("group_uuid")
    headers, records = itemgetter("headers", "records")(
        check_results.get("csv_records")
    )
    valid_file = validate_sources(headers, records)

    if type(valid_file) is list:
        return rest_bad_req(valid_file)

    header = {"Authorization", f"Bearer {token}"}
    entity_response = {}
    status_codes = []
    row_num = 1
    if valid_file is True:
        entity_created = False
        entity_failed_to_create = False
        for item in records:
            item["lab_source_id"] = item["lab_id"]
            del item["lab_id"]
            item["protocol_url"] = item["selection_protocol"]
            del item["selection_protocol"]
            item["description"] = item["lab_notes"]
            del item["lab_notes"]
            if group_uuid is not None:
                item["group_uuid"] = group_uuid
            r = requests.post(
                ensureTrailingSlashURL(current_app.config["ENTITY_WEBSERVICE_URL"])
                + "entities/source",
                headers=header,
                json=item,
            )
            entity_response[row_num] = r.json()
            row_num = row_num + 1
            status_codes.append(r.status_code)
            if r.status_code > 399:
                entity_failed_to_create = True
            else:
                entity_created = True
        return _send_response_on_file(
            entity_created,
            entity_failed_to_create,
            entity_response,
            _get_status_code_by_priority(status_codes),
        )


def _check_request_for_bulk():
    request_data = request.get_json()
    try:
        temp_id = request_data["temp_id"]
    except KeyError:
        return rest_bad_req("No key `temp_id` in request body")
    group_uuid = None
    if "group_uuid" in request_data:
        group_uuid = request_data["group_uuid"]
    temp_dir = current_app.config["FILE_UPLOAD_TEMP_DIR"]
    tsv_directory = os.path.join(temp_dir, temp_id)
    if not os.path.exists(tsv_directory):
        return rest_bad_req(
            f"Temporary file with id {temp_id} does not have a temp directory"
        )
    fcount = 0
    temp_file_name = None
    for tfile in os.listdir(tsv_directory):
        fcount = fcount + 1
        temp_file_name = tfile
    if fcount == 0:
        return rest_bad_req(f"File not found in temporary directory /{temp_id}")
    if fcount > 1:
        return rest_bad_req(f"Multiple files found in temporary file path /{temp_id}")
    file_location = tsv_directory + temp_file_name
    return {"csv_records": get_csv_records(file_location), "group_uuid": group_uuid}


def _send_response_on_file(
    entity_created: bool,
    entity_failed_to_create: bool,
    entity_response,
    status_code=StatusCodes.SERVER_ERR,
):
    if entity_created and not entity_failed_to_create:
        return rest_ok(entity_response)
    elif entity_created and entity_failed_to_create:
        return rest_response(
            StatusCodes.OK_PARTIAL,
            "Partial Success - Some Entities Created Successfully",
            entity_response,
        )
    else:
        return rest_response(
            status_code,
            f"entity_created: {entity_created}, entity_failed_to_create: {entity_failed_to_create}",
            entity_response,
        )


def _get_status_code_by_priority(codes):
    if StatusCodes.SERVER_ERR in codes:
        return StatusCodes.SERVER_ERR
    elif StatusCodes.UNACCEPTABLE in codes:
        return StatusCodes.UNACCEPTABLE
    else:
        return codes[0]
