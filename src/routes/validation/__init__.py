import csv
import logging
import os
import time
from uuid import uuid4

from atlas_consortia_commons.rest import (
    StatusCodes,
    abort_internal_err,
    full_response,
    is_json_request,
    rest_server_err,
)
from flask import Blueprint, jsonify, request
from rq.job import JobStatus

from lib.decorators import require_valid_token
from lib.file import check_upload, get_base_path, get_csv_records, set_file_details
from tasks import TaskQueue, create_queue_id
from tasks.validation import validate_uploaded_metadata

validation_blueprint = Blueprint("validation", __name__)
logger = logging.getLogger(__name__)


@validation_blueprint.route("/metadata/validate", methods=["POST"])
@require_valid_token(param="token", user_id_param="user_id")
def validate_metadata_upload(token: str, user_id: str):
    if is_json_request():
        data = request.json
    else:
        data = request.values

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

    task_queue = TaskQueue.instance()
    task_id = uuid4()
    queue_id = create_queue_id(user_id, task_id)

    job = task_queue.queue.enqueue(
        validate_uploaded_metadata,
        kwargs={
            "task_id": task_id,
            "upload": upload,
            "data": dict(data),
            "token": token,
        },
        job_id=queue_id,
        job_timeout=600,  # 10 minutes
        ttl=604800,  # 1 week
        result_ttl=604800,
        error_ttl=604800,
        description=f"Metadata {upload.get('filename')} validation",
    )

    status = job.get_status()
    if status == JobStatus.FAILED:
        abort_internal_err("Validation task failed to start")

    return jsonify({"task_id": task_id, "status": status}), 202


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
