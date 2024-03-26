from rq.job import Job, JobStatus

from jobs import JobResult, split_queue_id


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
        "referrer": job.meta.get("referrer", {}),
        "description": job.description,
        "status": status.title(),
        "user": job.meta.get("user", {}),
        "started_timestamp": (
            int(job.started_at.timestamp() * 1000) if job.started_at else None
        ),
        "ended_timestamp": (
            int(job.ended_at.timestamp() * 1000) if job.ended_at else None
        ),
        "results": results,
        "errors": errors,
    }
