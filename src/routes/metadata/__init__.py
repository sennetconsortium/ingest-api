import csv
import logging
import os
import time
from http.client import HTTPException
from uuid import uuid4

from atlas_consortia_commons.decorator import (
    User,
    require_json,
    require_multipart_form,
    require_valid_token,
)
from atlas_consortia_commons.rest import (
    StatusCodes,
    abort_bad_req,
    abort_internal_err,
    abort_not_found,
    full_response,
    rest_server_err,
)
from atlas_consortia_commons.string import equals
from flask import Blueprint, jsonify, Response, current_app
from hubmap_commons.hm_auth import AuthHelper
from hubmap_sdk import EntitySdk
from rq.job import Job, JobStatus, NoSuchJobError

from jobs import (
    JOBS_PREFIX,
    JobQueue,
    JobResult,
    JobSubject,
    JobType,
    JobVisibility,
    TooManyJobsFoundError,
    create_job_description,
    create_queue_id,
    get_display_job_status,
    update_job_metadata,
)
from jobs.registration.metadata import register_uploaded_metadata
from jobs.validation.metadata import validate_uploaded_metadata
from lib.file import check_upload, get_base_path, get_csv_records, set_file_details
from lib.services import obj_to_dict, entity_json_dumps, get_token, get_entity_by_id
from lib.ontology import Ontology
from lib.request_validation import get_validated_job_id, get_validated_referrer

metadata_blueprint = Blueprint("metadata", __name__)
logger = logging.getLogger(__name__)


@metadata_blueprint.route("/metadata/validate", methods=["POST"])
@require_valid_token()
@require_multipart_form(combined_param="data")
def validate_metadata_upload(data: dict, token: str, user: User):
    try:
        entity_type, sub_type = get_validated_entity_type(data)
        referrer = get_validated_referrer(data, JobType.VALIDATE)
    except ValueError as e:
        abort_bad_req(str(e))

    pathname = data.get("pathname")
    tsv_row = data.get("tsv_row")
    if pathname is None:
        upload = check_metadata_upload()
    else:
        if tsv_row is None:
            upload = set_file_details(pathname)
        else:
            upload = create_tsv_from_path(get_base_path() + pathname, int(tsv_row))

    error = upload.get("error")
    if error is not None:
        return full_response(error)

    job_queue = JobQueue.instance()
    job_id = uuid4()
    desc = create_job_description(
        JobSubject.METADATA,
        JobType.VALIDATE,
        entity_type,
        sub_type,
        upload.get("filename"),
    )

    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=validate_uploaded_metadata,
        job_kwargs={
            "job_id": job_id,
            "upload": upload,
            "data": dict(data),
            "token": token,
        },
        user={"id": user.uuid, "email": user.email},
        description=desc,
        metadata={"referrer": referrer, "register_job_id": None},
    )

    status = job.get_status()
    if status == JobStatus.FAILED:
        abort_internal_err("Validation job failed to start")

    display_status = get_display_job_status(job)
    return jsonify({"job_id": job_id, "status": display_status}), 202


@metadata_blueprint.route("/metadata/register", methods=["POST"])
@require_valid_token()
@require_json(param="body")
def register_metadata_upload(body: dict, token: str, user: User):
    try:
        validation_job_id = get_validated_job_id(body)
        referrer = get_validated_referrer(body, JobType.REGISTER)
    except ValueError as e:
        abort_bad_req(str(e))

    job_queue = JobQueue.instance()
    try:
        if user.is_data_admin is True:
            # Admin registering for a user
            scan_query = f"{JOBS_PREFIX}*:{validation_job_id}"
            validation_job = job_queue.query_job(scan_query)
            if (
                    validation_job.meta.get("visibility", JobVisibility.PUBLIC)
                    != JobVisibility.PUBLIC
            ):
                raise NoSuchJobError("Job is not marked PUBLIC")
        else:
            validation_queue_id = create_queue_id(user.uuid, validation_job_id)
            validation_job = Job.fetch(validation_queue_id, connection=job_queue.redis)

    except NoSuchJobError as e:
        logger.error(f"Validation job not found: {e}")
        abort_not_found("Validation job not found")
    except TooManyJobsFoundError as e:
        logger.error(f"Multiple jobs found with id {validation_job_id}: {e}")
        abort_internal_err("Multiple jobs found with job id")

    if validation_job.get_status() != JobStatus.FINISHED:
        abort_bad_req("Validation job has not completed")

    if validation_job.meta.get("register_job_id") is not None:
        abort_bad_req("Registration job already started")

    validation_result: JobResult = validation_job.result
    if validation_result.success is False or "file" not in validation_result.results:
        abort_bad_req("Validation job failed")

    subject = validation_result.results.get("subject")
    if not equals(subject, JobSubject.METADATA):
        abort_bad_req("Validation job was not for metadata")

    metadata_filepath = validation_result.results.get("file")
    job_id = uuid4()
    desc = validation_job.description.replace(
        JobType.VALIDATE.noun, JobType.REGISTER.noun
    )

    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=register_uploaded_metadata,
        job_kwargs={
            "job_id": job_id,
            "metadata_file": metadata_filepath,
            "token": token,
        },
        user={"id": user.uuid, "email": user.email},
        description=desc,
        metadata={"referrer": referrer},
    )

    status = job.get_status()
    if status == JobStatus.FAILED:
        abort_internal_err("Validation job failed to start")

    # Save the register job id to the validation job meta
    update_job_metadata(validation_job, {"register_job_id": job_id})

    display_status = get_display_job_status(job)
    return jsonify({"job_id": job_id, "status": display_status}), 202


# Fetch all Data Provider groups through Hubmap Commons
# Returns an Array of nested objects containing all groups
@metadata_blueprint.route('/metadata/data-provider-groups', methods=['GET'])
@require_valid_token()
def get_all_data_provider_groups(token: str, user: User):
    try:
        auth_helper_instance = AuthHelper.instance()
        group_list = auth_helper_instance.getHuBMAPGroupInfo()
        return_list = []
        for group_info in group_list.keys():
            if group_list[group_info]['data_provider'] == True:
                return_list.append(group_list[group_info])
        return jsonify({'groups': return_list}), 200
    except HTTPException as hte:
        return Response(hte.get_description(), hte.get_status_code())
    except Exception as e:
        logger.error(e, exc_info=True)
        return Response("Unexpected error while fetching group list: " + str(e) + "  Check the logs", 500)


@metadata_blueprint.route('/metadata/provenance-metadata/<ds_uuid>', methods=['GET'])
def get_provenance_metadata(ds_uuid: str):
    token = get_token()
    entity_instance = EntitySdk(token=token, service_url=current_app.config['ENTITY_WEBSERVICE_URL'])
    entity = get_entity_by_id(ds_uuid)

    if not equals(entity.entity_type, Ontology.ops().entities().DATASET):
        abort_bad_req(f"Entity with UUID: {ds_uuid} is not of type 'Dataset'")

    metadata_json_object = entity_json_dumps(entity, token, entity_instance, False)
    return jsonify(metadata_json_object), 200


def check_metadata_upload():
    """Checks the uploaded file.

    Returns
    -------
    dict
        A dictionary of containing upload details or an 'error' key if something went wrong.
    """

    result: dict = {"error": None}
    file_upload = check_upload("metadata")
    if file_upload.get("code") is StatusCodes.OK:
        file = file_upload.get("description")
        file_id = file.get("id")
        file = file.get("file")
        pathname = file_id + os.sep + file.filename
        result = set_file_details(pathname)
    else:
        result["error"] = file_upload

    return result


def create_tsv_from_path(path, row):
    """
    Creates a tsv from path of a specific row.
    This is in order to validate only one if necessary.

    Parameters
    ----------
    path : str
        Path of original tsv
    row : int
        Row number in tsv to extract for new tsv

    Returns
    -------
    dict
        A dictionary containing file details
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


def get_validated_entity_type(data: dict) -> str:
    entity_type = data.get("entity_type")
    sub_type = data.get("sub_type")

    e = Ontology.ops().entities()
    allowed_entity_types = [e.SOURCE, e.SAMPLE]
    if entity_type not in allowed_entity_types:
        raise ValueError(f"Invalid entity type {entity_type}")

    if equals(entity_type, e.SOURCE):
        s = Ontology.ops().source_types()
        if sub_type not in [s.MOUSE]:
            raise ValueError(f"Invalid source sub-type {sub_type}")

    if equals(entity_type, e.SAMPLE):
        s = Ontology.ops().specimen_categories()
        if sub_type not in [s.BLOCK, s.SECTION, s.SUSPENSION]:
            raise ValueError(f"Invalid sample sub-type {sub_type}")

    return entity_type, sub_type
