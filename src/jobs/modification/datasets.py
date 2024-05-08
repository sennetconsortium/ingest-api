import logging

from jobs import JobResult
from lib.services import bulk_update_entities

logger = logging.getLogger(__name__)


def update_datasets(job_id: str, dataset_updates: list, token: str):
    update_payload = {ds.pop("uuid"): ds for ds in dataset_updates}

    # send the dataset updates to entity-api
    update_res = bulk_update_entities(update_payload, token)

    for uuid, res in update_res.items():
        if not res["success"]:
            logger.error(f"Failed to update dataset {uuid}: {res['data']}")

    all_completed = all(res["success"] for res in update_res.values())
    job_results = [
        {
            "uuid": uuid,
            "success": res["success"],
            "message": res["data"] if not res["success"] else "Success",
        }
        for uuid, res in update_res.items()
    ]

    return JobResult(success=all_completed, results=job_results)
