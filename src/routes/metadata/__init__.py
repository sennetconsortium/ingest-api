import csv
import json
import logging
import os
import time
from urllib.parse import urlparse
from uuid import uuid4

from atlas_consortia_commons.rest import (
    StatusCodes,
    abort_bad_req,
    abort_internal_err,
    abort_not_found,
    full_response,
    rest_server_err,
)
from flask import Blueprint, jsonify
from rq.job import Job, JobStatus, NoSuchJobError

from jobs import JobQueue, JobResult, JobType, create_queue_id
from jobs.registration import register_uploaded_metadata
from jobs.validation import validate_uploaded_metadata
from lib.decorators import require_multipart_form, require_valid_token, require_json
from lib.file import check_upload, get_base_path, get_csv_records, set_file_details

metadata_blueprint = Blueprint("metadata", __name__)
logger = logging.getLogger(__name__)


@metadata_blueprint.route("/metadata/validate", methods=["POST"])
@require_valid_token(param="token", user_id_param="user_id")
@require_multipart_form(combined_param="data")
def validate_metadata_upload(data: dict, token: str, user_id: str):
    try:
        referrer = validate_referrer(data, JobType.VALIDATE)
    except ValueError as e:
        logger.error(f"Invalid referrer: {e}")
        abort_bad_req("Invalid referrer")

    pathname = data.get("pathname")
    tsv_row = data.get("tsv_row")
    if pathname is None:
        upload = check_metadata_upload()
    else:
        if tsv_row is None:
            upload = set_file_details(pathname)
        else:
            upload = create_tsv_from_path(get_base_path() + pathname, int(tsv_row))

    error = upload.get("error")
    if error is not None:
        return full_response(error)

    job_queue = JobQueue.instance()
    job_id = uuid4()
    queue_id = create_queue_id(user_id, job_id)

    job = job_queue.queue.enqueue(
        validate_uploaded_metadata,
        kwargs={
            "job_id": job_id,
            "upload": upload,
            "data": dict(data),
            "token": token,
        },
        job_id=queue_id,
        job_timeout=18000,  # 5 hours
        ttl=604800,  # 1 week
        result_ttl=604800,
        error_ttl=604800,
        description=f"Metadata {upload.get('filename')} validation",
    )

    # Add metadata to the job
    job.meta["referrer"] = referrer
    job.save()

    status = job.get_status()
    if status == JobStatus.FAILED:
        abort_internal_err("Validation job failed to start")

    return jsonify({"job_id": job_id, "status": status}), 202


@metadata_blueprint.route("/metadata/register", methods=["POST"])
@require_valid_token(param="token", user_id_param="user_id")
@require_json(param="body")
def register_metadata_upload(body: dict, token: str, user_id: str):
    if not isinstance(body, dict):
        abort_bad_req("Invalid request body")

    try:
        referrer = validate_referrer(body, JobType.REGISTER)
    except ValueError as e:
        logger.error(f"Invalid referrer: {e}")
        abort_bad_req("Invalid referrer")

    validation_job_id = body.get("job_id")
    if validation_job_id is None:
        abort_bad_req("Missing job_id in request body")

    job_queue = JobQueue.instance()
    validation_queue_id = create_queue_id(user_id, validation_job_id)
    try:
        validation_job = Job.fetch(validation_queue_id, connection=job_queue.redis)
    except NoSuchJobError as e:
        logger.error(f"Validation job not found: {e}")
        abort_not_found("Validation job not found")

    if validation_job.get_status() != JobStatus.FINISHED:
        abort_bad_req("Validation job has not completed")

    validation_result: JobResult = validation_job.result
    if validation_result.success is False or "file" not in validation_result.results:
        abort_bad_req("Validation job failed")

    metadata_filepath = validation_result.results.get("file")
    job_id = uuid4()
    queue_id = create_queue_id(user_id, job_id)

    job = job_queue.queue.enqueue(
        register_uploaded_metadata,
        kwargs={
            "job_id": job_id,
            "metadata_file": metadata_filepath,
            "token": token,
        },
        job_id=queue_id,
        job_timeout=18000,  # 5 hours
        ttl=604800,  # 1 week
        result_ttl=604800,
        error_ttl=604800,
        description=f"Metadata {validation_job_id} registration",
    )

    # Add metadata to the job
    job.meta["referrer"] = referrer
    job.save()

    status = job.get_status()
    if status == JobStatus.FAILED:
        abort_internal_err("Validation job failed to start")

    return jsonify({"job_id": job_id, "status": status}), 202


def check_metadata_upload():
    """Checks the uploaded file.

    Returns
    -------
    dict
        A dictionary of containing upload details or an 'error' key if something went wrong.
    """

    result: dict = {"error": None}
    file_upload = check_upload("metadata")
    if file_upload.get("code") is StatusCodes.OK:
        file = file_upload.get("description")
        file_id = file.get("id")
        file = file.get("file")
        pathname = file_id + os.sep + file.filename
        result = set_file_details(pathname)
    else:
        result["error"] = file_upload

    return result


def create_tsv_from_path(path, row):
    """
    Creates a tsv from path of a specific row.
    This is in order to validate only one if necessary.

    Parameters
    ----------
    path : str
        Path of original tsv
    row : int
        Row number in tsv to extract for new tsv

    Returns
    -------
    dict
        A dictionary containing file details
    """

    result: dict = {"error": None}
    try:
        records = get_csv_records(path, records_as_arr=True)
        result = set_file_details(f"{time.time()}.tsv")

        with open(result.get("fullpath"), "wt") as out_file:
            tsv_writer = csv.writer(out_file, delimiter="\t")
            tsv_writer.writerow(records.get("headers"))
            tsv_writer.writerow(records.get("records")[row])
    except Exception as e:
        result = rest_server_err(e, True)

    return result


def validate_referrer(data: dict, job_type: JobType) -> dict:
    referrer = data.get("referrer", "{}")
    if isinstance(referrer, str):
        referrer = json.loads(referrer)

    if "type" not in referrer or referrer["type"] != job_type.value:
        raise ValueError(f"Invalid referrer {referrer}")

    if "path" not in referrer:
        raise ValueError("Missing referrer URL")

    path = referrer["path"].replace(" ", "")
    parsed = urlparse(path)
    if parsed.scheme != "" or parsed.netloc != "" or len(parsed.path) < 1:
        raise ValueError(f"Invalid referrer URL {path}")

    query = f"?{parsed.query}" if parsed.query else ""
    return {
        "type": job_type.value,
        "path": f"{parsed.path}{query}",
    }
