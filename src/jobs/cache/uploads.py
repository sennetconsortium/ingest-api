import logging
import time
from datetime import timedelta
from uuid import uuid4

from hubmap_commons import string_helper
from rq import get_current_connection, get_current_job

from jobs import (
    JobQueue,
    JobResult,
    JobStatus,
    JobType,
    JobVisibility,
    update_job_progress,
)
from lib import get_globus_url
from lib.neo4j_helper import Neo4jHelper

logger = logging.getLogger(__name__)

UPLOADS_DATASTATUS_JOB_ID = "update_uploads_datastatus"
UPLOADS_DATASTATUS_JOB_PREFIX = "update_uploads_datastatus"


def schedule_update_uploads_datastatus(job_queue: JobQueue, delta: timedelta = timedelta(hours=1)):
    job_id = uuid4()
    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=update_uploads_datastatus,
        job_kwargs={},
        user={"id": UPLOADS_DATASTATUS_JOB_PREFIX, "email": UPLOADS_DATASTATUS_JOB_PREFIX},
        description="Update uploads datastatus",
        metadata={
            "omit_results": True,  # omit results from job endpoints
            "scheduled_for_timestamp": int((time.time() + delta.total_seconds()) * 1000),
            "referrer": {"type": JobType.CACHE.value, "path": ""},
        },
        visibility=JobVisibility.ADMIN,
        at_datetime=delta,
    )

    status = job.get_status()
    if status == JobStatus.FAILED:
        logger.error(
            f"Failed to schedule update uploads datastatus job: {job_id}: {job.get_error()}"
        )


def update_uploads_datastatus(schedule_next_job=True):
    try:
        logger.info("Starting update uploads datastatus")
        start = time.perf_counter()

        all_uploads_query = (
            "MATCH (up:Upload) "
            "OPTIONAL MATCH (up)<-[:IN_UPLOAD]-(ds:Dataset) "
            "RETURN up.uuid AS uuid, up.group_name AS group_name, up.sennet_id AS sennet_id, up.status AS status, "
            "up.title AS title, up.assigned_to_group_name AS assigned_to_group_name, "
            "up.intended_source_type AS intended_source_type, "
            "up.intended_organ AS intended_organ, up.intended_dataset_type AS intended_dataset_type, "
            "up.anticipated_complete_upload_month AS anticipated_complete_upload_month, up.anticipated_dataset_count AS anticipated_dataset_count, "
            "up.ingest_task AS ingest_task, COLLECT(DISTINCT ds.uuid) AS datasets"
        )

        displayed_fields = [
            "uuid",
            "group_name",
            "sennet_id",
            "status",
            "title",
            "datasets",
            "intended_source_type",
            "intended_organ",
            "intended_dataset_type",
            "assigned_to_group_name",
            "anticipated_complete_upload_month",
            "anticipated_dataset_count",
            "ingest_task",
        ]

        current_job = get_current_job()
        with Neo4jHelper.get_instance().session() as session:
            results = session.run(all_uploads_query).data()
            percent_delta = 100 / len(results) if results else 100
            for idx, upload in enumerate(results):
                globus_url = get_globus_url(
                    "protected", upload.get("group_name"), upload.get("uuid")
                )
                upload["globus_url"] = globus_url
                for prop in upload:
                    if isinstance(upload[prop], list):
                        upload[prop] = ", ".join(upload[prop])

                    if isinstance(upload[prop], (bool, int)):
                        upload[prop] = str(upload[prop])

                    if (
                        isinstance(upload[prop], str)
                        and len(upload[prop]) >= 2
                        and upload[prop][0] == "["
                        and upload[prop][-1] == "]"
                    ):
                        # For cases like `"ingest_task": "[Empty directory]"` we should not
                        # convert to a list. Converting will cause a ValueError. Leave it
                        # as the original value and move on
                        try:
                            prop_as_list = string_helper.convert_str_literal(upload[prop])
                            if len(prop_as_list) > 0:
                                upload[prop] = prop_as_list
                            else:
                                upload[prop] = ""
                        except ValueError:
                            pass

                    if upload[prop] is None:
                        upload[prop] = ""

                for field in displayed_fields:
                    if upload.get(field) is None:
                        upload[field] = ""

                if current_job is not None:
                    update_job_progress(percent_delta * (idx + 1), current_job)

        if current_job is not None:
            update_job_progress(100, current_job)
        logger.info(
            f"Finished updating uploads datastatus in {time.perf_counter() - start:.2f} seconds"
        )

        return JobResult(
            success=True, results={"data": results, "last_updated": int(time.time() * 1000)}
        )

    except Exception as e:
        logger.error(f"Failed to update uploads datastatus: {e}", exc_info=True)
        raise e
    finally:
        if schedule_next_job:
            # Schedule the next cache job
            connection = get_current_connection()
            job_queue = JobQueue(connection)
            schedule_update_uploads_datastatus(job_queue)
