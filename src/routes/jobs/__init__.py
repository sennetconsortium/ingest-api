import logging
from uuid import UUID

from atlas_consortia_commons.rest import (
    abort_bad_req,
    abort_internal_err,
    abort_not_found,
)
from flask import Blueprint, jsonify
from rq.job import InvalidJobOperation, Job, JobStatus, NoSuchJobError

from jobs import JobQueue, JobResult, create_queue_id, split_queue_id
from lib.decorators import require_data_admin, require_valid_token

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

    # this returns a list of byte objects
    prefix = "rq:job:"
    queue_ids = [
        queue_id.decode("utf-8").removeprefix(prefix)
        for queue_id in redis.scan_iter(f"{prefix}{user_id}:*")
    ]
    jobs = Job.fetch_many(queue_ids, connection=redis)
    res = [job_to_response(job) for job in jobs]
    return jsonify(res), 200


@jobs_blueprint.route("/jobs/flush", methods=["DELETE"])
@require_data_admin()
def flush_jobs():
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()

    finished_jobs = job_queue.queue.finished_job_registry
    for job_id in finished_jobs.get_job_ids():
        finished_jobs.remove(job_id, delete_job=True)

    failed_jobs = job_queue.queue.failed_job_registry
    for job_id in failed_jobs.get_job_ids():
        failed_jobs.remove(job_id, delete_job=True)

    canceled_jobs = job_queue.queue.canceled_job_registry
    for job_id in canceled_jobs.get_job_ids():
        canceled_jobs.remove(job_id, delete_job=True)

    return {"status": "success", "message": "All jobs have been deleted"}, 200


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


def job_to_response(job: Job) -> dict:
    _, job_id = split_queue_id(job.id)
    status = job.get_status()
    results = None
    errors = None
    if status == JobStatus.FINISHED:
        result: JobResult = job.result
        status = "complete" if result.success else "error"
        results = result.results if result.success else None
        errors = result.results if not result.success else None

    return {
        "job_id": job_id,
        "description": job.description,
        "status": status.title(),
        "started_timestamp": (
            int(job.started_at.timestamp() * 1000) if job.started_at else None
        ),
        "ended_timestamp": (
            int(job.ended_at.timestamp() * 1000) if job.ended_at else None
        ),
        "results": results,
        "errors": errors,
    }
