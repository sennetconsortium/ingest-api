import json
import logging
import os
from operator import itemgetter
from urllib.parse import urljoin

import requests
from atlas_consortia_commons.object import enum_val_lower
from atlas_consortia_commons.string import equals
from flask import Response, current_app
from hubmap_commons.file_helper import ensureTrailingSlashURL

from jobs import JobResult, JobSubject, update_job_progress
from lib.datacite_doi_helper import DataCiteDoiHelper
from lib.entities import (
    append_constraints_list,
    build_constraint_unit,
    common_ln_errs,
    get_as_list,
)
from lib.file import get_csv_records, ln_err, set_file_details
from lib.ontology import Ontology, get_organ_types_ep

logger = logging.getLogger(__name__)


def validate_uploaded_entities(
    job_id: str, entity_type: str, upload: dict, token: str, group_uuid: str
) -> JobResult:
    try:
        csv_records = get_csv_records(upload.get("fullpath"))
        if isinstance(csv_records, Response):
            message = (
                "Unable to read the uploaded file. Please ensure the file is a valid tsv file."
            )
            update_job_progress(100)
            return JobResult(success=False, results={"message": message})

        file_headers, records = itemgetter("headers", "records")(csv_records)

        if equals(entity_type, Ontology.ops().entities().SOURCE):
            valid_file = validate_sources(file_headers, records)
        elif equals(entity_type, Ontology.ops().entities().SAMPLE):
            header = {"Authorization": f"Bearer {token}"}
            valid_file = validate_samples(file_headers, records, header)
        else:
            logger.error(f"Validation job submitted for invalid entity type: {entity_type}")
            valid_file = False

        if valid_file is True:
            file_details = save_validation_records(records, entity_type, upload, job_id)
            update_job_progress(100)
            return JobResult(
                success=True,
                results={
                    "job_id": job_id,
                    "entity_type": entity_type,
                    "file": file_details.get("pathname"),
                    "group_uuid": group_uuid,
                    "subject": JobSubject.ENTITY.title(),
                },
            )
        elif type(valid_file) is list:
            update_job_progress(100)
            return JobResult(success=False, results=valid_file)
        else:
            update_job_progress(100)
            message = f"Unexpected error occurred while validating tsv file. Expecting valid_file to be of type List or Boolean but got type {type(valid_file)}"
            return JobResult(success=False, results={"message": message})

    except Exception as e:
        update_job_progress(100)
        logger.error(f"Error bulk validating {entity_type}: {e}")
        raise


def save_validation_records(records: dict, entity_type: str, upload: dict, job_id: str) -> dict:
    """Save the validated records from the uploaded tsv file to a file named
    <tmp_dir>/<job_id>_{entity_type}_results.json.

    This depends on the current job context. Can only be called within a job.

    Parameters
    ----------
    records : dict
        The validated records from the uploaded tsv file.
    entity_type : str
        The entity type being validated.
    upload : dict
        The upload file details.
    job_id : str
        The current job UUID.

    Returns
    -------
    dict
        The file details of the saved file.
    """
    fullpath = upload.get("pathname")
    dir_path = os.path.dirname(fullpath)
    results_path = os.path.join(dir_path, f"{job_id}_{entity_type.lower()}_results.json")

    file_details = set_file_details(results_path)
    with open(file_details.get("fullpath"), "w") as f:
        json.dump(records, f, separators=(",", ":"))
        return file_details


def validate_sources(headers, records):
    error_msg = []
    file_is_valid = True
    allowed_source_types = Ontology.ops(as_arr=True, cb=enum_val_lower).source_types()

    required_headers = ["lab_id", "source_type", "selection_protocol", "lab_notes"]
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(common_ln_errs(1, field))
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(common_ln_errs(2, field))
    rownum = 0
    if file_is_valid is True:
        for data_row in records:
            # validate that no fields in data_row are none. If they are none, then we cannot verify even if the entry we
            # are validating is what it is supposed to be. Mark the entire row as bad if a none field exists.
            rownum = rownum + 1
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(common_ln_errs(4, rownum))
                continue

            # validate that no headers are None. This indicates that there are fields present.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(common_ln_errs(6, rownum))
                continue

            # validate lab_id
            lab_id = data_row["lab_id"]
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(ln_err("must be fewer than 1024 characters", rownum, "lab_id"))
            if len(lab_id) < 1:
                file_is_valid = False
                error_msg.append(ln_err("must have 1 or more characters", rownum, "lab_id"))

            # validate selection_protocol
            protocol = data_row["selection_protocol"]
            doi_helper = DataCiteDoiHelper()
            if doi_helper.is_invalid_doi(protocol):
                file_is_valid = False
                error_msg.append(
                    ln_err(
                        "must either be of the format `https://dx.doi.org/##.####/protocols.io.*` or `dx.doi.org/##.####/protocols.io.*`",
                        rownum,
                        "selection_protocol",
                    )
                )

            # validate source_type
            if data_row["source_type"].lower() not in allowed_source_types:
                file_is_valid = False
                error_msg.append(
                    ln_err(
                        f"can only be one of the following (not case sensitive): {', '.join(allowed_source_types)}",
                        rownum,
                        "source_type",
                    )
                )

            # validate description
            description = data_row["lab_notes"]
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(
                    ln_err("must be fewer than 10,000 characters", rownum, "lab_notes")
                )

    if file_is_valid:
        return file_is_valid

    if file_is_valid is False:
        return error_msg


def validate_samples(headers, records, header):
    error_msg = []
    file_is_valid = True

    required_headers = [
        "ancestor_id",
        "sample_category",
        "preparation_protocol",
        "lab_id",
        "lab_notes",
        "organ_type",
        "rui_location",
    ]
    for field in required_headers:
        if field not in headers:
            file_is_valid = False
            error_msg.append(common_ln_errs(1, field))
    required_headers.append(None)
    for field in headers:
        if field not in required_headers:
            file_is_valid = False
            error_msg.append(common_ln_errs(2, field))

    allowed_categories = Ontology.ops(as_arr=True, cb=enum_val_lower).specimen_categories()
    # Get the ontology classes
    SpecimenCategories = Ontology.ops().specimen_categories()
    Entities = Ontology.ops().entities()

    organ_types_codes = list(
        Ontology.ops(as_data_dict=True, key="rui_code", val_key="term").organ_types().keys()
    )
    organ_types_codes.remove("OT")

    rownum = 0
    valid_ancestor_ids = []
    entity_constraint_list = []
    if file_is_valid is True:
        for data_row in records:
            # validate that no fields in data_row are none. If they are none, then we cannot verify even if the entry we
            # are validating is what it is supposed to be. Mark the entire row as bad if a none field exists.
            rownum = rownum + 1
            none_present = False
            for each in data_row.keys():
                if data_row[each] is None:
                    none_present = True
            if none_present:
                file_is_valid = False
                error_msg.append(common_ln_errs(4, rownum))
                continue

            # validate that no headers are None. This indicates that there are fields present.
            if data_row.get(None) is not None:
                file_is_valid = False
                error_msg.append(common_ln_errs(6, rownum))
                continue

            # validate description
            description = data_row["lab_notes"]
            if len(description) > 10000:
                file_is_valid = False
                error_msg.append(
                    ln_err("must be fewer than 10,000 characters", rownum, "lab_notes")
                )

            # validate preparation_protocol
            protocol = data_row["preparation_protocol"]
            doi_helper = DataCiteDoiHelper()
            if doi_helper.is_invalid_doi(protocol):
                file_is_valid = False
                error_msg.append(
                    ln_err(
                        "must either be of the format `https://dx.doi.org/##.####/protocols.io.*` or `dx.doi.org/##.####/protocols.io.*`",
                        rownum,
                        "preparation_protocol",
                    )
                )
            if len(protocol) < 1:
                file_is_valid = False
                error_msg.append(
                    ln_err(
                        "is a required filed and cannot be blank",
                        rownum,
                        "preparation_protocol",
                    )
                )

            # validate lab_id
            lab_id = data_row["lab_id"]
            if len(lab_id) > 1024:
                file_is_valid = False
                error_msg.append(ln_err("must be fewer than 1024 characters", rownum, "lab_id"))
            if len(lab_id) < 1:
                file_is_valid = False
                error_msg.append(ln_err("value cannot be blank", rownum, "lab_id"))

            # validate sample_category
            valid_category = True
            sample_category = data_row["sample_category"]
            if sample_category.lower() not in allowed_categories:
                file_is_valid = False
                valid_category = False
                error_msg.append(
                    ln_err(
                        f"can only be one of the following (not case sensitive): {', '.join(allowed_categories)}",
                        rownum,
                        "sample_category",
                    )
                )

            # validate organ_type
            data_row["organ_type"] = data_row["organ_type"].upper()
            organ_type = data_row["organ_type"]
            if not equals(sample_category, SpecimenCategories.ORGAN):
                if len(organ_type) > 0:
                    file_is_valid = False
                    error_msg.append(
                        ln_err(
                            "field must be blank if `sample_category` is not `organ`",
                            rownum,
                            "organ_type",
                        )
                    )
            if equals(sample_category, SpecimenCategories.ORGAN):
                if len(organ_type) < 1:
                    file_is_valid = False
                    error_msg.append(
                        ln_err(
                            "field is required if `sample_category` is `organ`",
                            rownum,
                            "organ_type",
                        )
                    )
            if len(organ_type) > 0:
                if organ_type not in organ_types_codes:
                    file_is_valid = False
                    error_msg.append(
                        ln_err(
                            f"value must be an organ code listed at {get_organ_types_ep()} and not 'OT'",
                            rownum,
                            "organ_type",
                        )
                    )

            # validate ancestor_id
            ancestor_id = data_row["ancestor_id"]
            validation_results = validate_ancestor_id(
                header,
                ancestor_id,
                error_msg,
                rownum,
                valid_ancestor_ids,
                file_is_valid,
            )

            (
                file_is_valid,
                error_msg,
                ancestor_saved,
                resp_status_code,
                ancestor_dict,
            ) = itemgetter(
                "file_is_valid",
                "error_msg",
                "ancestor_saved",
                "resp_status_code",
                "ancestor_dict",
            )(
                validation_results
            )

            if ancestor_saved or resp_status_code:
                data_row["ancestor_id"] = ancestor_dict["uuid"]
                if equals(sample_category, SpecimenCategories.ORGAN) and not equals(
                    ancestor_dict["type"], Entities.SOURCE
                ):
                    file_is_valid = False
                    error_msg.append(
                        ln_err(
                            "If `sample_category` is `organ`, `ancestor_id` must point to a source",
                            rownum,
                        )
                    )

                if not equals(sample_category, SpecimenCategories.ORGAN) and not equals(
                    ancestor_dict["type"], Entities.SAMPLE
                ):
                    file_is_valid = False
                    error_msg.append(
                        ln_err(
                            "If `sample_category` is not `organ`, `ancestor_id` must point to a sample",
                            rownum,
                        )
                    )

                # prepare entity constraints for validation
                sub_type = None
                sub_type_val = None
                if valid_category:
                    sub_type = get_as_list(sample_category)
                if equals(sample_category, SpecimenCategories.ORGAN):
                    sub_type_val = get_as_list(organ_type)

                entity_to_validate = build_constraint_unit(Entities.SAMPLE, sub_type, sub_type_val)
                try:
                    entity_constraint_list = append_constraints_list(
                        entity_to_validate,
                        ancestor_dict,
                        header,
                        entity_constraint_list,
                        ancestor_id,
                    )

                except Exception as e:
                    file_is_valid = False
                    error_msg.append(
                        ln_err(
                            f"Unable to access Entity Api during constraint validation. Received response: {e}",
                            rownum,
                        )
                    )

            # validate rui_location
            rui_location = data_row.get("rui_location")
            if rui_location:
                if equals(sample_category, SpecimenCategories.BLOCK):
                    # sample is a block and rui_location is provided
                    if organ_type not in ["AD", "BD", "BM", "BS", "BX", "MU", "OT"]:
                        # organ type is supported
                        try:
                            # check if rui_location is valid JSON
                            data_row["rui_location"] = json.loads(rui_location)
                        except json.JSONDecodeError as e:
                            logger.error(f"Error decoding JSON: {e}")
                            file_is_valid = False
                            error_msg.append(
                                ln_err(
                                    "value must be valid JSON",
                                    rownum,
                                    "rui_location",
                                )
                            )

                        try:
                            # check if associated sources support rui_location
                            url = urljoin(
                                current_app.config["ENTITY_WEBSERVICE_URL"],
                                f"ancestors/{ancestor_id}",
                            )
                            resp = requests.post(
                                url,
                                headers=header,
                                json={"filter_properties": ["source_type"], "is_include": True},
                            )
                            if resp.status_code == 404:
                                file_is_valid = False
                                error_msg.append(common_ln_errs(8, rownum))
                            if resp.status_code > 499:
                                file_is_valid = False
                                error_msg.append(common_ln_errs(5, rownum))
                            if resp.status_code == 401 or resp.status_code == 403:
                                file_is_valid = False
                                error_msg.append(common_ln_errs(7, rownum))
                            if resp.status_code == 400:
                                file_is_valid = False
                                error_msg.append(
                                    ln_err(f"`{ancestor_id}` is not a valid id format", rownum)
                                )
                            if resp.status_code < 300:
                                source_types = Ontology.ops().source_types()
                                ancestors = resp.json()
                                if not any(
                                    a["source_type"]
                                    in [source_types.HUMAN, source_types.HUMAN_ORGANOID]
                                    for a in ancestors
                                    if "source_type" in a
                                ):
                                    # sample is not associated with a human or human organoid source
                                    file_is_valid = False
                                    error_msg.append(
                                        ln_err(
                                            "entity must be associated with a human or human organoid source",
                                            rownum,
                                            "rui_location",
                                        )
                                    )
                        except Exception as e:
                            logger.error(f"Error validating rui_location: {e}")
                            file_is_valid = False
                            error_msg.append(common_ln_errs(5, rownum))
                else:
                    # rui_location is not support with this sample category
                    file_is_valid = False
                    error_msg.append(
                        ln_err(
                            f"field is not supported for sample category `{sample_category}`",
                            rownum,
                            "rui_location",
                        )
                    )

    # validate entity constraints
    return validate_entity_constraints(file_is_valid, error_msg, header, entity_constraint_list)


def validate_entity_constraints(file_is_valid, error_msg, header, entity_constraint_list):
    url = (
        ensureTrailingSlashURL(current_app.config["ENTITY_WEBSERVICE_URL"])
        + "constraints?match=true&report_type=ln_err"
    )
    try:
        validate_constraint_result = requests.post(url, headers=header, json=entity_constraint_list)
        if not validate_constraint_result.ok:
            constraint_errors = validate_constraint_result.json()
            error_msg.extend(constraint_errors.get("description"))
            file_is_valid = False
    except Exception as e:
        file_is_valid = False
        error_msg.append(common_ln_errs(3, e))
    if file_is_valid:
        return file_is_valid
    if file_is_valid is False:
        return error_msg


def validate_ancestor_id(header, ancestor_id, error_msg, rownum, valid_ancestor_ids, file_is_valid):
    if len(ancestor_id) < 1:
        file_is_valid = False
        error_msg.append(ln_err("cannot be blank", rownum, "ancestor_id"))
    if len(ancestor_id) > 0:
        ancestor_dict = {}
        ancestor_saved = False
        resp_status_code = False
        if len(valid_ancestor_ids) > 0:
            for item in valid_ancestor_ids:
                if item.get("uuid") or item.get("sennet_id"):
                    if ancestor_id == item["uuid"] or ancestor_id == item["sennet_id"]:
                        ancestor_dict = item
                        ancestor_saved = True
        if ancestor_saved is False:
            url = (
                ensureTrailingSlashURL(current_app.config["UUID_WEBSERVICE_URL"])
                + "uuid/"
                + ancestor_id
            )
            try:
                resp = requests.get(url, headers=header)
                if resp.status_code == 404:
                    file_is_valid = False
                    error_msg.append(common_ln_errs(8, rownum))
                if resp.status_code > 499:
                    file_is_valid = False
                    error_msg.append(common_ln_errs(5, rownum))
                if resp.status_code == 401 or resp.status_code == 403:
                    file_is_valid = False
                    error_msg.append(common_ln_errs(7, rownum))
                if resp.status_code == 400:
                    file_is_valid = False
                    error_msg.append(ln_err(f"`{ancestor_id}` is not a valid id format", rownum))
                if resp.status_code < 300:
                    ancestor_dict = resp.json()
                    valid_ancestor_ids.append(ancestor_dict)
                    resp_status_code = True
            except Exception:
                file_is_valid = False
                error_msg.append(common_ln_errs(5, rownum))

    return {
        "file_is_valid": file_is_valid,
        "error_msg": error_msg,
        "ancestor_dict": ancestor_dict,
        "resp_status_code": resp_status_code,
        "ancestor_saved": ancestor_saved,
    }
