import logging
import os
from operator import itemgetter
from uuid import uuid4

from atlas_consortia_commons.decorator import User, require_json, require_valid_token
from atlas_consortia_commons.rest import (
    abort_bad_req,
    abort_internal_err,
    abort_not_found,
)
from atlas_consortia_commons.string import equals
from flask import Blueprint, jsonify, request
from rq.job import Job, JobStatus, NoSuchJobError
from werkzeug.utils import secure_filename

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
from jobs.registration.entities import register_uploaded_entities
from jobs.validation.entities import validate_uploaded_entities
from lib.file import check_upload, set_file_details
from lib.ontology import Ontology
from lib.request_validation import (
    get_validated_group_uuid,
    get_validated_job_id,
    get_validated_referrer,
)

sources_blueprint = Blueprint("sources", __name__)
logger = logging.getLogger(__name__)


@sources_blueprint.route("/sources/bulk/validate", methods=["POST"])
@require_valid_token()
def bulk_sources_upload_and_validate(token: str, user: User):
    try:
        referrer = get_validated_referrer(request.form, JobType.VALIDATE)
        group_uuid = get_validated_group_uuid(request.form, user.group_uuids, user.is_data_admin)
    except ValueError as e:
        abort_bad_req(str(e))

    # save uploaded file to temp directory
    file_upload = check_upload()
    temp_id, file = itemgetter("id", "file")(file_upload.get("description"))

    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    file.filename = secure_filename(file.filename)
    pathname = os.path.join(temp_id, file.filename)
    upload = set_file_details(pathname)

    job_queue = JobQueue.instance()
    job_id = uuid4()
    desc = create_job_description(
        JobSubject.ENTITY,
        JobType.VALIDATE,
        "Source",
        None,
        upload.get("filename"),
    )

    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=validate_uploaded_entities,
        job_kwargs={
            "job_id": job_id,
            "entity_type": "Source",
            "upload": upload,
            "token": token,
            "group_uuid": group_uuid,
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


@sources_blueprint.route("/sources/bulk/register", methods=["POST"])
@require_valid_token()
@require_json(param="body")
def create_sources_from_bulk(body: dict, token: str, user: User):
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
            if validation_job.meta.get("visibility", JobVisibility.PUBLIC) != JobVisibility.PUBLIC:
                raise NoSuchJobError("Job is not marked PUBLIC")
        else:
            # User registering their own job
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

    entity_type = validation_result.results.get("entity_type")
    if not equals(entity_type, Ontology.ops().entities().SOURCE):
        abort_bad_req("Validation job was not for Source entities")

    group_uuid = validation_result.results.get("group_uuid")
    if group_uuid is None:
        abort_internal_err("Group UUID was not found in validation job")

    validation_filepath = validation_result.results.get("file")
    job_id = uuid4()
    desc = validation_job.description.replace(JobType.VALIDATE.noun, JobType.REGISTER.noun)

    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=register_uploaded_entities,
        job_kwargs={
            "job_id": job_id,
            "entity_type": "Source",
            "validation_file": validation_filepath,
            "token": token,
            "group_uuid": group_uuid,
        },
        user=validation_job.meta.get("user"),
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
