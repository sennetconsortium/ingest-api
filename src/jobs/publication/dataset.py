import logging

from flask import current_app
from hubmap_commons.file_helper import ensureTrailingSlashURL

from jobs import JobResult
from lib.ingest_file_helper import IngestFileHelper
from lib.slack import send_slack_notification

logger = logging.getLogger(__name__)


def copy_protect_files_to_public(job_id: str, dataset: dict) -> JobResult:
    if dataset.get("creation_action") != "Multi-Assay Split" and dataset.get("data_access_level") != "protected":
        return JobResult(success=True, results="Dataset is not a component dataset or protected, no files to copy")

    try:
        ingest_helper = IngestFileHelper(current_app.config)
        src_dir, dst_dir = ingest_helper.copy_protected_files_to_public(dataset)
        return JobResult(
            success=True,
            results=f"Copied protected files from {src_dir} to {dst_dir}",
        )
    except Exception as e:
        try:
            portal_url = ensureTrailingSlashURL(current_app.config["PORTAL_URL"])
            job_url = f"{portal_url}admin/jobs?q={job_id}"
            msg = (
                f"Error copying protected files for dataset {dataset.get('uuid')} during "
                f"publication. See job details at {job_url}"
            )
            send_slack_notification(msg)
        except Exception as slack_err:
            logger.error(f"Failed to send Slack notification for job {job_id}: {slack_err}")

        logger.error(f"Error copying protected files for dataset {dataset.get('uuid')}: {e}")
        return JobResult(success=False, results=f"Error copying protected files: {e}")
