import logging
from typing import Literal

import requests
from atlas_consortia_commons.string import equals
from flask import current_app
from hubmap_commons.file_helper import ensureTrailingSlashURL

from jobs import JobResult
from lib.dataset_helper import DatasetHelper
from lib.ontology import Ontology
from lib.services import bulk_update_entities

logger = logging.getLogger(__name__)


def submit_datasets_uploads_to_pipeline(
    job_id: str,
    entity_uuids: list,
    token: str,
    process: Literal["submit", "validate"],
    entity_type: Literal["Dataset", "Upload"] = "Dataset",
):
    config = current_app.config

    # change the status of the datasets/uploads to Processing using entity-api
    if equals(entity_type, Ontology.ops().entities().DATASET):
        update_payload = {
            uuid: {
                "status": "Processing",
                "ingest_id": "",
                "run_id": "",
                "pipeline_message": "",
            }
            for uuid in entity_uuids
        }
    else:
        update_payload = {
            uuid: {
                "status": "Processing",
                "ingest_id": "",
                "run_id": "",
                "validation_message": "",
            }
            for uuid in entity_uuids
        }
    update_status_res = bulk_update_entities(update_payload, token)

    # get the datasets/uploads that were successfully updated, log the ones that failed
    processing_entities = [
        entity["data"] for entity in update_status_res.values() if entity["success"]
    ]
    for uuid, res in update_status_res.items():
        if not res["success"]:
            logger.error(f"Failed to set dataset/upload status to processing {uuid}: {res['data']}")

    for processing_entity in processing_entities:
        logger.debug(f"Updated processing entity: {processing_entity}")

    # create the ingest_payload list
    dataset_helper = DatasetHelper(config)
    ingest_payload = [
        dataset_helper.create_ingest_payload(entity, process) for entity in processing_entities
    ]

    logger.info(f"Sending ingest payload to ingest-pipeline: {ingest_payload}")

    # submit the datasets/uploads to the processing pipeline
    ingest_pipline_url = (
        ensureTrailingSlashURL(config["INGEST_PIPELINE_URL"]) + "request_bulk_ingest"
    )
    try:
        ingest_res = requests.post(
            ingest_pipline_url,
            json=ingest_payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        logger.info(f"Response from ingest-pipeline {ingest_res.status_code}: {ingest_res.json()}")
    except requests.exceptions.RequestException as e:
        ingest_res = None
        logger.error(f"Failed to submit datasets/uploads to pipeline: {e}")

    if ingest_res is not None and (ingest_res.status_code == 200 or ingest_res.status_code == 400):
        # assumes a 200/400 status code with json of the form
        # 200:
        # {
        #   "response": [
        #     {
        #       "ingest_id": "",
        #       "run_id": "",
        #       "submission_id": ""
        #     }, ...
        #   ]
        # }
        #
        # 400:
        # {
        #   "response": {
        #     "error": [
        #       {
        #         "message": "",
        #         "submission_id" : "",
        #       }, ...
        #     ],
        #     "success":[
        #       {
        #         "ingest_id": "",
        #         "run_id": "",
        #         "submission_id": "",
        #       }, ...
        #     ]
        #   }
        # }

        # update the datasets/uploads with the received info from the pipeline
        pipeline_result = ingest_res.json().get("response", {})
        successful = (
            pipeline_result if ingest_res.status_code == 200 else pipeline_result.get("success", [])
        )
        update_payload = {
            s["submission_id"]: {"ingest_id": s["ingest_id"], "run_id": s["run_id"]}
            for s in successful
        }

        if ingest_res.status_code == 400:
            if equals(entity_type, Ontology.ops().entities().DATASET):
                error_payload = {
                    e["submission_id"]: {
                        "status": "Error",
                        "pipeline_message": e["message"],
                    }
                    for e in pipeline_result.get("error", [])
                }
            else:
                error_payload = {
                    e["submission_id"]: {
                        "status": "Error",
                        "validation_message": e["message"],
                    }
                    for e in pipeline_result.get("error", [])
                }
            update_payload.update(error_payload)

        update_res = bulk_update_entities(update_payload, token)

        # log the datasets/uploads that failed to update
        for uuid, res in update_res.items():
            if not res["success"]:
                logger.error(
                    "Failed to set dataset/upload ingest info or pipeline/validation message "
                    f"{uuid}: {res['data']}"
                )

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

    else:
        # request failed, update the datasets/uploads to error
        update_payload = {
            entity["uuid"]: {
                "status": "Error",
                "pipeline_message": "Failed to submit to pipeline",
            }
            for entity in processing_entities
        }
        update_errored_res = bulk_update_entities(update_payload, token)

        # log the datasets/uploads that failed to update
        for uuid, res in update_errored_res.items():
            if not res["success"]:
                logger.error(
                    f"Failed to set status and pipeline/validation message {uuid}: {res['data']}"
                )

        job_results = [
            {
                "uuid": uuid,
                "success": False,
                "message": (
                    f"Failed to set 'status' to 'Error': {res['data']}"
                    if not res["success"]
                    else "Set 'status' to 'Error'"
                ),
            }
            for uuid, res in update_errored_res.items()
        ]

        return JobResult(success=False, results=job_results)
