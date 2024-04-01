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
from atlas_consortia_commons.string import equals, to_title_case
from flask import current_app
from hubmap_commons.file_helper import ensureTrailingSlashURL
from ingest_validation_tools import schema_loader, table_validator
from ingest_validation_tools import validation_utils as iv_utils

from jobs import JobResult
from lib.file import get_csv_records, ln_err, set_file_details
from lib.ontology import Ontology

logger = logging.getLogger(__name__)


def validate_uploaded_metadata(
    job_id: str, upload: dict, data: dict, token: str
) -> JobResult:
    try:
        entity_type = data.get("entity_type")
        sub_type = data.get("sub_type")
        validate_uuids = data.get("validate_uuids")
        tsv_row = data.get("tsv_row")

        if check_cedar(entity_type, sub_type, upload) is False:
            logger.error(
                f"Error validating metadata: {entity_type} {sub_type} does not match metadata_schema_id"
            )
            id = get_cedar_schema_ids().get(sub_type)
            return JobResult(
                success=False,
                results={
                    "message": (
                        f'Mismatch of "{entity_type} {sub_type}" and "metadata_schema_id". '
                        f'Valid id for "{sub_type}": {id}. '
                        "For more details, check out the docs: https://docs.sennetconsortium.org/libraries/ingest-validation-tools/schemas"
                    )
                },
            )

        schema = determine_schema(entity_type, sub_type)
        validation_results = validate_tsv(
            token=token, path=upload.get("fullpath"), schema=schema
        )
        if len(validation_results) > 0:
            logger.error(f"Error validating metadata: {validation_results}")
            return JobResult(success=False, results=[validation_results])
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
                return JobResult(success=False, results=response.get("description"))

        metadata_details = save_metadata_results(response, upload, job_id)
        return JobResult(
            success=True,
            results={"job_id": job_id, "file": metadata_details.get("pathname")},
        )

    except Exception as e:
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
    token: str, schema: str = "metadata", path: Optional[str] = None
) -> dict:
    """Calls methods of the Ingest Validation Tools submodule.

    Parameters
    ----------
    token : str
        The groups_token to use for validation.
    schema : str
        Name of the schema to validate against. Defaults to "metadata".
    path : str, optional
        The path of the tsv for Ingest Validation Tools. Defaults to None.

    Returns
    -------
    dict
        A dictionary containing validation results.
    """

    try:
        schema_name = (
            schema
            if schema != "metadata"
            else iv_utils.get_schema_version(
                path, "ascii", globus_token=token
            ).schema_name
        )
    except schema_loader.PreflightError as e:
        result = rest_server_err({"Preflight": str(e)}, True)
    else:
        try:
            app_context = {
                "request_header": {"X-SenNet-Application": "ingest-api"},
                "entities_url": f"{ensureTrailingSlashURL(current_app.config['ENTITY_WEBSERVICE_URL'])}entities/",
            }
            result = iv_utils.get_tsv_errors(
                path,
                schema_name=schema_name,
                report_type=table_validator.ReportType.JSON,
                globus_token=token,
                app_context=app_context,
            )
            if "CEDAR Validation Errors" in result:
                if path in result["CEDAR Validation Errors"]:
                    result = result["CEDAR Validation Errors"][path]
                else:
                    result = result["CEDAR Validation Errors"]
        except Exception as e:
            result = rest_server_err(e, True)

    return result


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


def get_cedar_schema_ids() -> dict:
    """Returns the CEDAR schema ids for the different sample sub types.

    Returns
    -------
    dict
        A dictionary containing the schema ids for each sample sub type.
    """
    return {
        "Block": "3e98cee6-d3fb-467b-8d4e-9ba7ee49eeff",
        "Section": "01e9bc58-bdf2-49f4-9cf9-dd34f3cc62d7",
        "Suspension": "ea4fb93c-508e-4ec4-8a4b-89492ba68088",
    }


def check_cedar(entity_type, sub_type, upload):
    records = get_metadata(upload.get("fullpath"))
    if len(records) > 0:
        if (
            equals(entity_type, Ontology.ops().entities().SAMPLE)
            and "metadata_schema_id" in records[0]
        ):
            # TODO: check type of value schema for subtype
            # schema = iv_utils.get_schema_version(upload.get('fullpath'), encoding='ascii', globus_token=get_groups_token())
            # return equals(schema, f"{entity_type}-{sub_type}")
            cedar_sample_sub_type_ids = get_cedar_schema_ids()
            return equals(
                records[0]["metadata_schema_id"], cedar_sample_sub_type_ids[sub_type]
            )
    return True


def determine_schema(entity_type, sub_type):
    if equals(entity_type, Ontology.ops().entities().SOURCE):
        schema = "murine-source"
    elif equals(entity_type, Ontology.ops().entities().SAMPLE):
        if not sub_type:
            return rest_bad_req("`sub_type` for schema name required.")
        schema = f"sample-{sub_type}"
    else:
        schema = "metadata"

    schema = schema.lower()
    return schema


def _get_response(
    metadata, entity_type, sub_type, validate_uuids, token, pathname=None
):
    if validate_uuids == "1":
        response = validate_records_uuids(
            metadata, entity_type, sub_type, pathname, token
        )
    else:
        response = {"code": StatusCodes.OK, "pathname": pathname, "metadata": metadata}

    return response


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
    header = {"Authorization": f"Bearer {token}"}
    ok = True
    idx = 1
    for r in records:
        # First get the id column name, in order to get SenNet id in the record
        id_col = get_col_id_name_by_entity_type(entity_type)
        entity_id = r.get(id_col)
        # Use the SenNet id to find the stored entity
        url = (
            ensureTrailingSlashURL(current_app.config["ENTITY_WEBSERVICE_URL"])
            + "entities/"
            + entity_id
        )
        try:
            resp = requests.get(url, headers=header)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error validating metadata: {e}")
        if resp.status_code < 300:
            entity = resp.json()
            if sub_type is not None:
                sub_type_col = get_sub_type_name_by_entity_type(entity_type)
                _sub_type = entity.get(sub_type_col)
                # Check that the stored entity _sub_type is actually supported for validation
                if _sub_type not in supported_metadata_sub_types(entity_type):
                    ok = False
                    errors.append(
                        rest_response(
                            StatusCodes.UNACCEPTABLE,
                            StatusMsgs.UNACCEPTABLE,
                            ln_err(
                                f"of `{to_title_case(_sub_type)}` unsupported "
                                f"on check of given `{entity_id}`. "
                                f"Supported `{'`, `'.join(supported_metadata_sub_types(entity_type))}`.",
                                idx,
                                sub_type_col,
                            ),
                            dict_only=True,
                        )
                    )
                # Check that the stored entity _sub_type matches what is expected (the type being bulk uploaded)
                elif not equals(sub_type, _sub_type):
                    ok = False
                    ln = ln_err(
                        f"got `{to_title_case(_sub_type)}` on check of given `{entity_id}`, "
                        f"expected `{sub_type}` for `{sub_type_col}`.",
                        idx,
                        id_col,
                    )
                    err = rest_response(
                        StatusCodes.UNACCEPTABLE,
                        StatusMsgs.UNACCEPTABLE,
                        ln,
                        dict_only=True,
                    )
                    errors.append(err)
                else:
                    entity["metadata"] = r
                    passing.append(rest_ok(entity, True))
            else:
                entity["metadata"] = r
                passing.append(rest_ok(entity, True))
        else:
            ok = False
            ln = ln_err(f"invalid `{id_col}`: '{entity_id}'", idx, id_col)
            err = rest_response(
                resp.status_code, StatusMsgs.UNACCEPTABLE, ln, dict_only=True
            )
            errors.append(err)

        idx += 1

    if ok is True:
        return rest_ok({"data": passing, "pathname": pathname}, dict_only=True)
    else:
        return rest_response(
            StatusCodes.UNACCEPTABLE,
            "There are invalid `uuids` and/or unmatched entity sub types",
            errors,
            dict_only=True,
        )
