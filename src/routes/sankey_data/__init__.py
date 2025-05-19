import logging

from atlas_consortia_commons.rest import abort_internal_err
from flask import Blueprint, current_app, jsonify
from hubmap_commons.hm_auth import AuthHelper
from rq.exceptions import NoSuchJobError
from rq.job import JobStatus

from jobs import JOBS_PREFIX, JobQueue
from jobs.cache.datasets import (
    DATASETS_SANKEYDATA_JOB_CONSORTIUM_PREFIX,
    DATASETS_SANKEYDATA_JOB_PUBLIC_PREFIX,
    update_dataset_sankey_data,
)
from lib.services import get_token

sankey_data_blueprint = Blueprint("sankey_data", __name__)
logger = logging.getLogger(__name__)

DATASETS_SANKEY_DATA_KEY = "datasets_sankey_data_key"
DATASETS_SANKEY_DATA_LAST_UPDATED_KEY = "datasets_sankey_data_last_updated_key"


@sankey_data_blueprint.route("/datasets/sankey_data", methods=["GET"])
def get_ds_assaytype():
    token: str = get_token()
    authorized = False
    if token:
        auth_helper_instance: AuthHelper = AuthHelper.instance()
        authorized = auth_helper_instance.has_read_privs(token)

    if current_app.config.get("REDIS_MODE") is False:
        try:
            results = update_dataset_sankey_data(authorized, schedule_next_job=False)
            return jsonify(results.results)
        except Exception:
            abort_internal_err("Failed to retrieve datasets sankey data.")

    # Get jobs from rq
    try:
        job_queue = JobQueue.instance()

        scan_query = f"{JOBS_PREFIX}{DATASETS_SANKEYDATA_JOB_PUBLIC_PREFIX}:*"
        if authorized:
            scan_query = f"{JOBS_PREFIX}{DATASETS_SANKEYDATA_JOB_CONSORTIUM_PREFIX}:*"
        jobs = job_queue.query_jobs(scan_query)
        success_jobs = [job for job in jobs if job.get_status() == JobStatus.FINISHED]
        if len(success_jobs) == 0:
            raise NoSuchJobError
        if len(success_jobs) == 1:
            return jsonify(success_jobs[0].result.results)

        # Get the latest finished jobs
        newest_job = max(success_jobs, key=lambda j: j.ended_at)
        return jsonify(newest_job.result.results)

    except NoSuchJobError:
        return jsonify({"message": "Datasets sankey data is currently being cached"}), 202
