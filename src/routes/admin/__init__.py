import logging
from uuid import UUID

from atlas_consortia_commons.rest import (
    abort_bad_req,
    abort_internal_err,
    abort_not_found,
)
from flask import Blueprint, jsonify, request
from rq.job import InvalidJobOperation, JobStatus, NoSuchJobError

from jobs import JOBS_PREFIX, JobQueue
from lib import globus
from lib.decorators import require_data_admin
from lib.jobs import TooManyJobsFoundError, job_to_response, query_job, query_jobs

admin_blueprint = Blueprint("admin", __name__)
logger = logging.getLogger(__name__)


@admin_blueprint.route("/admin/jobs", methods=["GET"])
@require_data_admin()
def get_admin_jobs():
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    redis = job_queue.redis

    if request.args.get("email") is not None:
        # Support querying by email
        email = request.args.get("email")
        user_id = globus.get_user_id(email)
        if user_id is None:
            abort_not_found("User with email not found")
        scan_query = f"{JOBS_PREFIX}{user_id}:*"
    else:
        scan_query = f"{JOBS_PREFIX}*"

    jobs = query_jobs(scan_query, redis)
    res = [job_to_response(job) for job in jobs]
    return jsonify(res), 200


@admin_blueprint.route("/admin/jobs/<uuid:job_id>", methods=["GET"])
@require_data_admin()
def get_admin_job(job_id: UUID):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    redis = job_queue.redis

    scan_query = f"{JOBS_PREFIX}*:{job_id}"
    try:
        job = query_job(scan_query, redis)
    except NoSuchJobError as e:
        logger.error(f"Job not found: {e}")
        abort_not_found("Job not found")
    except TooManyJobsFoundError as e:
        logger.error(f"Multiple jobs found with id {job_id}: {e}")
        abort_internal_err("Multiple jobs found with job id")

    return job_to_response(job), 200


@admin_blueprint.route("/admin/jobs/<uuid:job_id>", methods=["DELETE"])
@require_data_admin()
def delete_admin_job(job_id: UUID):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    redis = job_queue.redis

    scan_query = f"{JOBS_PREFIX}*:{job_id}"
    try:
        job = query_job(scan_query, redis)
        job.delete()
    except NoSuchJobError as e:
        logger.error(f"Job not found: {e}")
        abort_not_found("Job not found")
    except TooManyJobsFoundError as e:
        logger.error(f"Multiple jobs found with id {job_id}: {e}")
        abort_internal_err("Multiple jobs found with job id")

    return {"status": "success", "message": "Job deleted successfully"}, 200


@admin_blueprint.route("/admin/jobs/<uuid:job_id>/cancel", methods=["PUT"])
@require_data_admin()
def cancel_admin_job(job_id: UUID):
    if JobQueue.is_initialized() is False:
        logger.error("Job queue has not been initialized")
        abort_internal_err("Unable to retrieve job information")

    job_queue = JobQueue.instance()
    redis = job_queue.redis

    scan_query = f"{JOBS_PREFIX}*:{job_id}"
    try:
        job = query_job(scan_query, redis)
    except NoSuchJobError as e:
        logger.error(f"Job not found: {e}")
        abort_not_found("Job not found")
    except TooManyJobsFoundError as e:
        logger.error(f"Multiple jobs found with id {job_id}: {e}")
        abort_internal_err("Multiple jobs found with job id")

    if job.get_status() in [JobStatus.FINISHED, JobStatus.FAILED]:
        abort_bad_req("Job has already been completed or failed")

    try:
        job.cancel()
    except InvalidJobOperation as e:
        logger.error(f"Job cannot be canceled: {e}")
        abort_bad_req("Job has already been canceled")

    return {}, 200


@admin_blueprint.route("/admin/jobs/flush", methods=["DELETE"])
@require_data_admin()
def flush_admin_jobs():
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
