import csv
import json
import logging
import os
import time
from typing import Optional

import requests
from atlas_consortia_commons.rest import (
    StatusCodes,
    StatusMsgs,
    rest_bad_req,
    rest_ok,
    rest_response,
    rest_server_err,
)
from atlas_consortia_commons.string import equals
from flask import current_app
from hubmap_commons.file_helper import ensureTrailingSlashURL
from ingest_validation_tools import schema_loader, table_validator
from ingest_validation_tools import validation_utils as iv_utils

from jobs import JobResult, JobSubject, update_job_progress
from lib.file import get_csv_records, ln_err, set_file_details
from lib.ontology import Ontology
from lib.services import get_auth_header_dict

logger = logging.getLogger(__name__)


def validate_uploaded_metadata(job_id: str, upload: dict, data: dict, token: str) -> JobResult:
    try:
        entity_type = data.get("entity_type")
        sub_type = data.get("sub_type")
        validate_uuids = data.get("validate_uuids")
        tsv_row = data.get("tsv_row")

        if spec_supported(upload) is False:
            logger.error(f"Unsupported spec: {entity_type} {sub_type}")
            update_job_progress(100)
            return JobResult(
                success=False,
                results={
                    "message": (
                        f'Unsupported uploaded TSV spec for "{entity_type} {sub_type}". CEDAR formatting is required for `{entity_type}`. '
                        "For more details, check out the docs: https://docs.sennetconsortium.org/libraries/ingest-validation-tools/schemas"
                    )
                },
            )
        validation_results = validate_tsv(
            token=token, entity_type=entity_type, sub_type=sub_type, path=upload.get("fullpath")
        )
        if validation_results.get("code") != StatusCodes.OK:
            _errors = validation_results.get("description")

            logger.error(f"Error validating metadata: {_errors}")
            update_job_progress(100)
            return JobResult(success=False, results=_errors)
        else:
            records = get_metadata(upload.get("fullpath"))
            response = _get_response(
                records,
                entity_type,
                sub_type,
                validate_uuids,
                token=token,
                pathname=upload.get("pathname"),
            )
            if tsv_row is not None:
                os.remove(upload.get("fullpath"))

            if response.get("code") != StatusCodes.OK:
                update_job_progress(100)
                return JobResult(success=False, results=response.get("description"))

        metadata_details = save_metadata_results(response, upload, job_id)
        update_job_progress(100)
        return JobResult(
            success=True,
            results={
                "job_id": job_id,
                "file": metadata_details.get("pathname"),
                "subject": JobSubject.METADATA.title(),
            },
        )

    except Exception as e:
        update_job_progress(100)
        logger.error(f"Error validating metadata: {e}")
        raise


def save_metadata_results(response: dict, upload: dict, job_id: str) -> dict:
    """Save the metadata results to a file named <tmp_dir>/<job_id>_metadata_results.json.

    This depends on the current job context. Can only be called within a job.

    Parameters
    ----------
    response : dict
        The result of the validation.
    upload : dict
        The upload file details.
    job_id : str
        The current job UUID.

    Returns
    -------
    dict
        The file details of the saved file.
    """
    # strip out the response information so we're left with just the entity information
    data = response.get("description", {}).get("data", [])
    entities = [d.get("description", {}) for d in data]

    fullpath = upload.get("pathname")
    dir_path = os.path.dirname(fullpath)
    metadata_results_path = os.path.join(dir_path, f"{job_id}_metadata_results.json")

    metadata_details = set_file_details(metadata_results_path)

    with open(metadata_details.get("fullpath"), "w") as f:
        json.dump(entities, f, separators=(",", ":"))
        return metadata_details


def get_metadata(path: str) -> list:
    """Parses a tsv and returns the rows of that tsv.

    Parameters
    ----------
    path : str
        The path where the tsv file is stored.

    Returns
    -------
    list
        A list of dictionaries.
    """

    result = get_csv_records(path)
    return result.get("records")


def validate_tsv(
    token: str,
    entity_type: str,
    sub_type: str,
    attribute: Optional[str] = "",
    latest_schema_name: Optional[str] = "isLatestVersion",
    path: Optional[str] = None,
) -> dict:
    """Calls methods of the Ingest Validation Tools submodule.

    Parameters
    ----------
    token : str
        The groups_token to use for validation.
    entity_type : str
        The entity type the user asserts this file is to be validated against.
    sub_type : str
        The sub type (block, section, suspension)  the user asserts this file is to be validated against.
    attribute : str, optional
        Used to check against the schema returned by the IVT in the case of 'contributors'
    latest_schema_name : str, optional
        Used to specify which version to check against. Values include:
            isLatestVersion,
            isLatestPublishedVersion,
            isLatestDraftVersion
    path : str, optional
        The path of the tsv for Ingest Validation Tools. Defaults to None.

    Returns
    -------
    dict
        A dictionary containing validation results in
        format of atlas_consortia_commons.rest.rest_response {code, name, description}
    """

    try:
        schema = iv_utils.get_schema_version(
            path=path,
            encoding="ascii",
            entity_url=f"{ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL'])}entities/",
            ingest_url=ensureTrailingSlashURL(current_app.config["INGEST_URL"]),
            globus_token=token,
        )

        # Check if the schema detected in the TSV matches the Entity/Subtype the user specified
        entity_type_info = schema.entity_type_info

        # First check is to handle `contributors` as `attribute` and the `entity_type_info.entity_type` will both equal "contributor"
        if not equals(entity_type_info.entity_type.value, attribute.lower()):
            # Check that the entity type/subtype specified by the user and what is determined by IV Utils are same
            if equals(entity_type_info.entity_type.value, entity_type.lower()):
                # Source (mouse) has no entity_type_info.entity_sub_type
                if not equals(entity_type_info.entity_sub_type, "") and not equals(
                    entity_type_info.entity_sub_type, sub_type.lower()
                ):
                    return rest_bad_req(
                        f'Mismatch of "{entity_type} {sub_type}" and "metadata_schema_id". '
                        f"File does match a valid Cedar schema. For more details, check out the docs: https://docs.sennetconsortium.org/libraries/ingest-validation-tools/schemas",
                        True,
                    )
            else:
                return rest_bad_req(
                    f'Mismatch of "{entity_type}" and "metadata_schema_id". '
                    f"File does match a valid Cedar schema. For more details, check out the docs: https://docs.sennetconsortium.org/libraries/ingest-validation-tools/schemas",
                    True,
                )

        if isinstance(schema, schema_loader.SchemaVersion):
            schema_name = schema.schema_name
            schema_version = schema.version
            if schema.is_cedar is False or not iv_utils.is_schema_latest_version(
                schema_version=schema_version,
                cedar_api_key=current_app.config["CEDAR_API_KEY"],
                latest_version_name=latest_schema_name,
            ):
                return rest_bad_req(
                    f"Outdated Cedar Metadata Schema ID detected: {schema_version}", True
                )

        app_context = {
            "request_header": {"X-SenNet-Application": "ingest-api"},
            "ingest_url": ensureTrailingSlashURL(current_app.config["INGEST_URL"]),
            "entities_url": f"{ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL'])}entities/",
            "constraints_url": f"{ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL'])}constraints/",
        }
        validation_results = iv_utils.get_tsv_errors(
            path,
            schema_name=schema_name,
            report_type=table_validator.ReportType.JSON,
            globus_token=token,
            app_context=app_context,
        )
        if len(validation_results) == 0:
            validation_results = get_csv_records(path)
            return rest_response(StatusCodes.OK, "TSV validation results", validation_results, True)
        else:
            final_results = []

            def parse_results(record):
                if isinstance(record, dict):
                    if "description" in record:
                        parse_results(record["description"])
                    if "column" in record and "error" in record and "row" in record:
                        # TODO: remove logic if it ever starts at the usual 0 from IVT
                        # IVT returns rows beginning at 1, reduce for regular reading on client end
                        record["row"] = record["row"] - 1 if record["row"] > 0 else None
                        final_results.append(record)
                    else:
                        # some unexpected dict, just str it and append to results
                        final_results.append(ln_err(str(record)))
                elif isinstance(record, list):
                    for item in record:
                        parse_results(item)
                elif isinstance(record, Exception):
                    ex = record.args[0]
                    final_results.append(
                        ln_err(
                            f"{ex.get('message', '')} {ex.get('cause', '')} {ex.get('fixSuggestion', '')}"
                        )
                    )
                else:
                    # some other instance, maybe str or some other object
                    final_results.append(ln_err(str(record)))

            for r in validation_results:
                parse_results(r)

            return rest_bad_req(final_results, True)

    except schema_loader.PreflightError as e:
        validation_results = rest_server_err({"Preflight": str(e)}, True)
    except Exception as e:
        validation_results = rest_server_err(e, True)

    return validation_results


def create_tsv_from_path(path: str, row: int) -> dict:
    """Creates a tsv from path of a specific row.

    This is in order to validate only one if necessary.

    Parameters
    ----------
    path : str
        Path of original tsv.
    row : int
        Row number in tsv to extract for new tsv.

    Returns
    -------
    dict
        A dictionary containing file details.
    """

    result: dict = {"error": None}
    try:
        records = get_csv_records(path, records_as_arr=True)
        result = set_file_details(f"{time.time()}.tsv")

        with open(result.get("fullpath"), "wt") as out_file:
            tsv_writer = csv.writer(out_file, delimiter="\t")
            tsv_writer.writerow(records.get("headers"))
            tsv_writer.writerow(records.get("records")[row])
    except Exception as e:
        result = rest_server_err(e, True)

    return result


def spec_supported(upload):
    fullpath = upload.get("fullpath")
    records = get_metadata(fullpath)
    return len(records) and "metadata_schema_id" in records[0]


def _get_response(metadata, entity_type, sub_type, validate_uuids, token, pathname=None):
    if validate_uuids == "1":
        response = validate_records_uuids(metadata, entity_type, sub_type, pathname, token)
    else:
        response = {"code": StatusCodes.OK, "pathname": pathname, "metadata": metadata}

    return response


def get_related_col_id_by_entity_type(entity_type: str) -> str:
    """Returns an additional tsv id column name for the given entity type.

    Parameters
    ----------
    entity_type : str
        The entity type.

    Returns
    -------
    str
        The name of the column in the tsv.
    """

    if equals(entity_type, Ontology.ops().entities().SAMPLE):
        return "source_id"


def get_col_id_name_by_entity_type(entity_type: str) -> str:
    """Returns the tsv id column name for the given entity type.

    Parameters
    ----------
    entity_type : str
        The entity type.

    Returns
    -------
    str
        The name of the column in the tsv.
    """

    if equals(entity_type, Ontology.ops().entities().SAMPLE):
        return "sample_id"
    else:
        return "source_id"


def get_sub_type_name_by_entity_type(entity_type):
    if equals(entity_type, Ontology.ops().entities().SAMPLE):
        return "sample_category"
    else:
        return "source_type"


def supported_metadata_sub_types(entity_type):
    if equals(entity_type, Ontology.ops().entities().SOURCE):
        return [Ontology.ops().source_types().MOUSE]
    else:
        return [
            Ontology.ops().specimen_categories().BLOCK,
            Ontology.ops().specimen_categories().SECTION,
            Ontology.ops().specimen_categories().SUSPENSION,
        ]


def fetch_entity(token, entity_id, id_col, idx, errors):
    if entity_id is None:
        err = rest_bad_req(
            ln_err(f"Must supply `{id_col}` and valid value", idx, id_col),
            dict_only=True,
        )
        errors.append(err)
        return False

    try:
        url = (
            ensureTrailingSlashURL(current_app.config["ENTITY_WEBSERVICE_URL"])
            + "entities/"
            + entity_id
        )
        resp = requests.get(url, headers=get_auth_header_dict(token))
    except requests.exceptions.RequestException as e:
        logger.error(f"Error validating metadata: {e}")

    if resp.status_code < 300:
        return resp.json()
    else:
        ln = ln_err(f"Invalid `{id_col}`: `{entity_id}`", idx, id_col)
        err = rest_response(resp.status_code, StatusMsgs.UNACCEPTABLE, ln, dict_only=True)
        errors.append(err)
        return False


def validate_records_uuids(
    records: list, entity_type: str, sub_type: str, pathname: str, token: str
) -> dict:
    """Validates the uuids / SenNet ids of given records.

    This is used for bulk upload so that ancestor ids referenced by the user in TSVs
    are found to actually exist, are supported and confirm to entity constraints.

    Parameters
    ----------
    records : list
        The set of records to validate.
    entity_type : str
        The entity type.
    sub_type : str
        The sub type of the entity.
    pathname : str
        The pathname of the tsv.
        (This is always returned in the response for tracking and other re-validation purposes.)
    token : str
        The groups_token to use for validation.

    Returns
    -------
    dict
        atlas_consortia_commons.rest.rest_response dict containing results of validation
    """
    errors = []
    passing = []
    idx = 1

    fail_response = rest_response(
        StatusCodes.UNACCEPTABLE,
        "There are invalid `uuids` and/or unmatched entity sub types",
        errors,
        dict_only=True,
    )

    for r in records:
        ok = True
        # First get the id column name, in order to get SenNet id in the record
        id_col = get_col_id_name_by_entity_type(entity_type)
        entity_id = r.get(id_col).strip()
        entity = fetch_entity(token, entity_id, id_col, idx, errors)

        if entity is False:
            return fail_response

        result_entity = {"uuid": entity["uuid"]}

        # Check that any additional entities mentioned in tsv exists; currently only relevant for Samples
        if get_related_col_id_by_entity_type(entity_type) is not None:
            related_id_col = get_related_col_id_by_entity_type(entity_type)
            related_entity_id = r.get(related_id_col).strip()
            if related_entity_id is not None:
                related_entity = fetch_entity(token, related_entity_id, related_id_col, idx, errors)
                if related_entity is False:
                    ok = False
            else:
                return rest_bad_req(
                    (
                        f'Unsupported uploaded TSV spec for "{entity_type} {sub_type}". Missing `{related_id_col}` column. '
                        "For more details, check out the docs: https://docs.sennetconsortium.org/libraries/ingest-validation-tools/schemas"
                    ),
                    dict_only=True,
                )

        if sub_type is not None:
            sub_type_col = get_sub_type_name_by_entity_type(entity_type)
            _sub_type = entity.get(sub_type_col).strip()
            # Check that the stored entity _sub_type is actually supported for validation
            if _sub_type not in supported_metadata_sub_types(entity_type):
                ok = False
                errors.append(
                    rest_bad_req(
                        ln_err(
                            f"of `{_sub_type}` unsupported "
                            f"on check of given `{entity_id}`. "
                            f"Supported `{'`, `'.join(supported_metadata_sub_types(entity_type))}`.",
                            idx,
                            sub_type_col,
                        ),
                        dict_only=True,
                    )
                )
            # Check that the stored entity _sub_type matches what is expected (the type being bulk uploaded)
            if not equals(sub_type, _sub_type):
                ok = False
                errors.append(
                    rest_bad_req(
                        ln_err(
                            f"got `{_sub_type}` on check of given `{entity_id}`, "
                            f"expected `{sub_type}` for `{sub_type_col}`.",
                            idx,
                            id_col,
                        ),
                        dict_only=True,
                    )
                )

        if ok is True:
            result_entity["metadata"] = r
            passing.append(rest_ok(result_entity, True))

        idx += 1

    if len(errors) == 0:
        return rest_ok({"data": passing, "pathname": pathname}, dict_only=True)
    else:
        return fail_response
