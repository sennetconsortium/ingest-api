import logging
from uuid import UUID

from atlas_consortia_commons.rest import abort_internal_err, abort_not_found
from flask import Blueprint
from rq.job import Job, NoSuchJobError

from lib.decorators import require_valid_token
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

    return {
        "task_id": task_id,
        "description": job.meta.get("description"),
        "status": job.get_status().title(),
        "started_timestamp": int(job.started_at.timestamp() * 1000)if job.started_at else None,
        "ended_timestamp": int(job.ended_at.timestamp() * 1000) if job.ended_at else None,
        "results": job.result
    }, 200
