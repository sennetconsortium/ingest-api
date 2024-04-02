import logging
import os
from operator import itemgetter
from uuid import uuid4

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
    JobQueue,
    JobResult,
    JobSubject,
    JobType,
    create_job_description,
    create_queue_id,
)
from jobs.registration.entities import register_uploaded_entities
from jobs.validation.entities import validate_uploaded_entities
from lib.decorators import require_json, require_valid_token
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
@require_valid_token(param="token", user_id_param="user_id", email_param="email")
def bulk_sources_upload_and_validate(token: str, user_id: str, email: str):
    try:
        referrer = get_validated_referrer(request.form, JobType.VALIDATE)
    except ValueError as e:
        logger.error(f"Invalid referrer: {e}")
        abort_bad_req("Invalid referrer")

    # save uploaded file to temp directory
    file_upload = check_upload()
    temp_id, file = itemgetter("id", "file")(file_upload.get("description"))

    # uses csv.DictReader to add functionality to tsv file. Can do operations on rows and headers.
    file.filename = secure_filename(file.filename)
    pathname = os.path.join(temp_id, file.filename)
    upload = set_file_details(pathname)

    job_queue = JobQueue.instance()
    job_id = uuid4()
    queue_id = create_queue_id(user_id, job_id)
    desc = create_job_description(
        JobSubject.ENTITY,
        JobType.VALIDATE,
        "Source",
        None,
        upload.get("filename"),
    )

    job = job_queue.queue.enqueue(
        validate_uploaded_entities,
        kwargs={
            "job_id": job_id,
            "entity_type": "Source",
            "upload": upload,
            "token": token,
        },
        job_id=queue_id,
        job_timeout=18000,  # 5 hours
        ttl=604800,  # 1 week
        result_ttl=604800,
        error_ttl=604800,
        description=desc,
    )

    # Add metadata to the job
    job.meta["referrer"] = referrer
    job.meta["user"] = {"id": user_id, "email": email}
    job.save()

    status = job.get_status()
    if status == JobStatus.FAILED:
        abort_internal_err("Validation job failed to start")

    return jsonify({"job_id": job_id, "status": status}), 202


@sources_blueprint.route("/sources/bulk/register", methods=["POST"])
@require_valid_token(
    param="token",
    user_id_param="user_id",
    email_param="email",
    groups_param="group_ids",
    is_data_admin_param="is_admin",
)
@require_json(param="body")
def create_sources_from_bulk(
    body: dict, token: str, user_id: str, email: str, group_ids: list, is_admin: bool
):
    if not isinstance(body, dict):
        abort_bad_req("Invalid request body")

    try:
        validation_job_id = get_validated_job_id(body)
        group_uuid = get_validated_group_uuid(body, group_ids, is_admin)
        referrer = get_validated_referrer(body, JobType.REGISTER)
    except ValueError as e:
        abort_bad_req(str(e))

    job_queue = JobQueue.instance()
    validation_queue_id = create_queue_id(user_id, validation_job_id)
    try:
        validation_job = Job.fetch(validation_queue_id, connection=job_queue.redis)
    except NoSuchJobError as e:
        logger.error(f"Validation job not found: {e}")
        abort_not_found("Validation job not found")

    if validation_job.get_status() != JobStatus.FINISHED:
        abort_bad_req("Validation job has not completed")

    validation_result: JobResult = validation_job.result
    if validation_result.success is False or "file" not in validation_result.results:
        abort_bad_req("Validation job failed")

    entity_type = validation_result.results.get("entity_type")
    if not equals(entity_type, Ontology.ops().entities().SOURCE):
        abort_bad_req("Validation job was not for Source entities")

    validation_filepath = validation_result.results.get("file")
    job_id = uuid4()
    queue_id = create_queue_id(user_id, job_id)
    desc = validation_job.description.replace(
        JobType.VALIDATE.noun, JobType.REGISTER.noun
    )

    job = job_queue.queue.enqueue(
        register_uploaded_entities,
        kwargs={
            "job_id": job_id,
            "entity_type": "Source",
            "validation_file": validation_filepath,
            "token": token,
            "group_uuid": group_uuid,
        },
        job_id=queue_id,
        job_timeout=18000,  # 5 hours
        ttl=604800,  # 1 week
        result_ttl=604800,
        error_ttl=604800,
        description=desc,
    )

    # Add metadata to the job
    job.meta["referrer"] = referrer
    job.meta["user"] = {"id": user_id, "email": email}
    job.save()

    status = job.get_status()
    if status == JobStatus.FAILED:
        abort_internal_err("Validation job failed to start")

    return jsonify({"job_id": job_id, "status": status}), 202
