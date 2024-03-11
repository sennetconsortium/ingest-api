import logging

import requests
from hubmap_commons.file_helper import ensureTrailingSlashURL

from lib.services import bulk_update_entities
from routes.entity_CRUD.dataset_helper import DatasetHelper

logger = logging.getLogger(__name__)


def submit_datasets(dataset_uuids: list, token: str, config: dict):
    entity_api_url = config["ENTITY_WEBSERVICE_URL"]

    # change the status of the datasets to Processing using entity-api
    update_payload = {uuid: {"status": "Processing"} for uuid in dataset_uuids}
    update_status_res = bulk_update_entities(
        update_payload, token, entity_api_url=entity_api_url
    )

    # get the datasets that were successfully updated, log the ones that failed
    processing_datasets = [
        dataset["data"] for dataset in update_status_res.values() if dataset["success"]
    ]
    for uuid, res in update_status_res.items():
        if not res["success"]:
            logger.error(
                f"Failed to set dataset status to processing {uuid}: {res['data']}"
            )

    # create the ingest_payload list
    dataset_helper = DatasetHelper(config)
    ingest_payload = [
        dataset_helper.create_ingest_payload(dataset) for dataset in processing_datasets
    ]

    # submit the datasets to the processing pipeline
    ingest_pipline_url = (
        ensureTrailingSlashURL(config["INGEST_PIPELINE_URL"]) + "/datasets/bulk/submit"
    )
    try:
        ingest_res = requests.post(
            ingest_pipline_url,
            json=ingest_payload,
            headers={"Authorization": f"Bearer {token}"},
        )
    except requests.exceptions.RequestException as e:
        ingest_res = None
        logger.error(f"Failed to submit datasets to pipeline: {e}")

    if ingest_res and ingest_res.status_code == 202:
        # Assumes a 202 status code with json of the form. This may change.
        # {
        #   "uuid": {
        #       "status": "success",
        #       "ingest_id": "uuid",
        #       "run_id": "uuid"
        #   },
        #   "uuid": {
        #       "status": "error",
        #       "message": "error message"
        #   }
        # }
        # successful request, could have errored datasets though
        pipeline_result = ingest_res.json()
        update_payload = {}
        for uuid, info in pipeline_result.items():
            if info["status"] == "success":
                update_payload[uuid] = {
                    "ingest_id": info["ingest_id"],
                    "run_id": info["run_id"],
                }
            else:
                update_payload[uuid] = {
                    "status": "Error",
                    "pipeline_message": info["message"],
                }
        update_res = bulk_update_entities(
            update_payload, token, entity_api_url=entity_api_url
        )

        # log the datasets that failed to update
        for uuid, res in update_res.items():
            if not res["success"]:
                logger.error(
                    f"Failed to set dataset ingest info or pipeline message {uuid}: "
                    f"{res['data']}"
                )

    else:
        update_payload = {
            dataset["uuid"]: {
                "status": "Error",
                "pipeline_message": "Failed to submit to pipeline",
            }
            for dataset in processing_datasets
        }
        update_errored_res = bulk_update_entities(
            update_payload, token, entity_api_url=entity_api_url
        )

        # log the datasets that failed to update
        for uuid, res in update_errored_res.items():
            if not res["success"]:
                logger.error(
                    f"Failed to set status and pipeline message {uuid}: {res['data']}"
                )
