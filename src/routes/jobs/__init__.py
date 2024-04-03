import logging
from uuid import UUID

from atlas_consortia_commons.rest import (
    abort_bad_req,
    abort_internal_err,
    abort_not_found,
)
from flask import Blueprint, jsonify
from rq.job import InvalidJobOperation, Job, JobStatus, NoSuchJobError

from jobs import JOBS_PREFIX, JobQueue, create_queue_id, job_to_response
from lib.decorators import User, require_valid_token

jobs_blueprint = Blueprint("jobs", __name__)
logger = logging.getLogger(__name__)


@jobs_blueprint.route("/jobs", methods=["GET"])
@require_valid_token()
def get_jobs(user: User):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()

    query = f"{JOBS_PREFIX}{user.uuid}:*"
    jobs = job_queue.query_jobs(query)
    res = [job_to_response(job) for job in jobs]
    return jsonify(res), 200


@jobs_blueprint.route("/jobs/<uuid:job_id>", methods=["GET"])
@require_valid_token()
def get_job(job_id: UUID, user: User):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    queue_id = create_queue_id(user.uuid, job_id)
    try:
        job = Job.fetch(queue_id, connection=job_queue.redis)
    except NoSuchJobError as e:
        logger.error(f"Job not found: {e}")
        abort_not_found("Job not found")

    return job_to_response(job), 200


@jobs_blueprint.route("/jobs/<uuid:job_id>", methods=["DELETE"])
@require_valid_token()
def delete_job(job_id: UUID, user: User):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    queue_id = create_queue_id(user.uuid, job_id)
    try:
        job = Job.fetch(queue_id, connection=job_queue.redis)
        job.delete()
    except NoSuchJobError as e:
        logger.error(f"Job not found: {e}")
        abort_not_found("Job not found")

    return {"status": "success", "message": "Job deleted successfully"}, 200


@jobs_blueprint.route("/jobs/<uuid:job_id>/cancel", methods=["PUT"])
@require_valid_token()
def cancel_job(job_id: UUID, user: User):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to cancel job")

    job_queue = JobQueue.instance()
    queue_id = create_queue_id(user.uuid, job_id)
    try:
        job = Job.fetch(queue_id, connection=job_queue.redis)
    except NoSuchJobError as e:
        logger.error(f"Job not found: {e}")
        abort_not_found("Job not found")

    if job.get_status() in [JobStatus.FINISHED, JobStatus.FAILED]:
        abort_bad_req("Job has already been completed or failed")

    try:
        job.cancel()
    except InvalidJobOperation as e:
        logger.error(f"Job cannot be canceled: {e}")
        abort_bad_req("Job has already been canceled")

    return {}, 200
