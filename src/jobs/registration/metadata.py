import json

from jobs import JobResult
from lib.file import set_file_details
from lib.services import bulk_update_entities


def register_uploaded_metadata(
    job_id: str, metadata_file: str, token: str
) -> JobResult:
    # Metadata should already be validated at this point
    upload = set_file_details(metadata_file)
    fullpath = upload.get("fullpath")
    with open(fullpath, "r") as f:
        entities = json.load(f)

    update_payload = {e["uuid"]: {"metadata": e["metadata"]} for e in entities}
    update_results = bulk_update_entities(update_payload, token)

    all_completed = all(v["success"] for v in update_results.values())

    # On success, we don't want to return the whole entity
    results = [
        {
            "uuid": k,
            "success": v["success"],
            "message": v["data"] if not v["success"] else "Success",
        }
        for k, v in update_results.items()
    ]
    return JobResult(success=all_completed, results=results)
