from redis import Redis
from rq.job import Job, JobStatus, NoSuchJobError

from jobs import JOBS_PREFIX, JobResult, split_queue_id


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


class TooManyJobsFoundError(Exception):
    pass


def query_job(query: str, redis: Redis) -> Job:
    """Get a RQ Job from Redis using a scan query.

    See Redis SCAN command for more information on the query format.

    Parameters
    ----------
    query : str
        The query to use to search for the job.
    redis : Redis
        The Redis connection to use.

    Returns
    -------
    Job
        The RQ Job object.

    Raises
    ------
    NoSuchJobError
        If the job is not found.
    TooManyJobsFoundError
        If multiple jobs are found with the query. Should not happen.
    """
    queue_ids = [
        queue_id.decode("utf-8").removeprefix(JOBS_PREFIX)
        for queue_id in redis.scan_iter(query)
    ]
    if len(queue_ids) == 0:
        raise NoSuchJobError("Job not found")
    if len(queue_ids) > 1:
        raise TooManyJobsFoundError("Multiple jobs found with from query")

    return Job.fetch(queue_ids[0], connection=redis)


def query_jobs(query: str, redis: Redis) -> list[Job]:
    """Get a list of RQ Jobs from Redis using a scan query.

    Parameters
    ----------
    query : str
        The query to use to search for the jobs.
    redis : Redis
        The Redis connection to use.

    Returns
    -------
    list[Job]
        The list of RQ Job objects.
    """
    queue_ids = [
        queue_id.decode("utf-8").removeprefix(JOBS_PREFIX)
        for queue_id in redis.scan_iter(query)
    ]
    return Job.fetch_many(queue_ids, connection=redis)
