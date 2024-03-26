import logging
from uuid import UUID

from atlas_consortia_commons.rest import (
    abort_bad_req,
    abort_internal_err,
    abort_not_found,
)
from flask import Blueprint, jsonify
from rq.job import InvalidJobOperation, Job, JobStatus, NoSuchJobError

from jobs import JobQueue, create_queue_id
from lib.decorators import require_valid_token
from lib.jobs import job_to_response

jobs_blueprint = Blueprint("jobs", __name__)
logger = logging.getLogger(__name__)


@jobs_blueprint.route("/jobs/<uuid:job_id>", methods=["GET"])
@require_valid_token(user_id_param="user_id")
def get_job(job_id: UUID, user_id: str):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    queue_id = create_queue_id(user_id, job_id)
    try:
        job = Job.fetch(queue_id, connection=job_queue.redis)
    except NoSuchJobError as e:
        logger.error(f"Job not found: {e}")
        abort_not_found("Job not found")

    return job_to_response(job), 200


@jobs_blueprint.route("/jobs/<uuid:job_id>", methods=["DELETE"])
@require_valid_token(user_id_param="user_id")
def delete_job(job_id: UUID, user_id: str):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    queue_id = create_queue_id(user_id, job_id)
    try:
        job = Job.fetch(queue_id, connection=job_queue.redis)
        job.delete()
    except NoSuchJobError as e:
        logger.error(f"Job not found: {e}")
        abort_not_found("Job not found")

    return {"status": "success", "message": "Job deleted successfully"}, 200


@jobs_blueprint.route("/jobs", methods=["GET"])
@require_valid_token(user_id_param="user_id")
def get_jobs(user_id: str):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    redis = job_queue.redis

    prefix = "rq:job:"
    scan_query = f"{prefix}{user_id}:*"

    # this returns a list of byte objects
    queue_ids = [
        queue_id.decode("utf-8").removeprefix(prefix)
        for queue_id in redis.scan_iter(scan_query)
    ]
    jobs = Job.fetch_many(queue_ids, connection=redis)
    res = [job_to_response(job) for job in jobs]
    return jsonify(res), 200


@jobs_blueprint.route("/jobs/<uuid:job_id>/cancel", methods=["PUT"])
@require_valid_token(user_id_param="user_id")
def cancel_job(job_id: UUID, user_id: str):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to cancel job")

    job_queue = JobQueue.instance()
    queue_id = create_queue_id(user_id, job_id)
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
