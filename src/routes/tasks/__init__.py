import logging
from uuid import UUID

from atlas_consortia_commons.rest import abort_internal_err, abort_not_found
from flask import Blueprint
from rq.job import Job, JobStatus, NoSuchJobError

from lib.decorators import require_data_admin, require_valid_token
from tasks import TaskQueue

tasks_blueprint = Blueprint("tasks", __name__)
logger = logging.getLogger(__name__)


@tasks_blueprint.route("/tasks/<uuid:task_id>", methods=["GET"])
@require_valid_token(user_id_param="user_id")
def get_task(task_id: UUID, user_id: str):
    if TaskQueue.is_initialized() is False:
        logger.error("Task queue has not been initialized")
        abort_internal_err("Unable to retrieve task information")

    task_queue = TaskQueue.instance()
    queue_id = task_queue.create_queue_id(user_id, task_id)
    try:
        job = Job.fetch(queue_id, connection=task_queue.redis)
    except NoSuchJobError as e:
        logger.error(f"Task not found: {e}")
        abort_not_found("Task not found")

    status = job.get_status()
    results = None
    errors = None
    if status == JobStatus.FINISHED:
        status = "complete" if job.result.get("success", False) else "error"
        results = job.result.get("results") if job.result["success"] else None
        errors = job.result.get("results") if not job.result["success"] else None

    return {
        "task_id": task_id,
        "description": job.meta.get("description"),
        "status": status.title(),
        "started_timestamp": (
            int(job.started_at.timestamp() * 1000) if job.started_at else None
        ),
        "ended_timestamp": (
            int(job.ended_at.timestamp() * 1000) if job.ended_at else None
        ),
        "results": results,
        "errors": errors,
    }, 200


@tasks_blueprint.route("/tasks/flush", methods=["DELETE"])
@require_data_admin()
def flush_tasks():
    if TaskQueue.is_initialized() is False:
        logger.error("Task queue has not been initialized")
        abort_internal_err("Unable to retrieve task information")

    task_queue = TaskQueue.instance()

    finished_jobs = task_queue.queue.finished_job_registry
    for job_id in finished_jobs.get_job_ids():
        finished_jobs.remove(job_id, delete_job=True)

    failed_jobs = task_queue.queue.failed_job_registry
    for job_id in failed_jobs.get_job_ids():
        failed_jobs.remove(job_id, delete_job=True)

    return {"status": "success", "message": "All tasks have been deleted"}, 200
