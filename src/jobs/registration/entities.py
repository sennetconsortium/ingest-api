import json

from atlas_consortia_commons.string import equals

from jobs import JobResult, update_job_progress
from lib.file import set_file_details
from lib.ontology import Ontology
from lib.services import bulk_create_entities


def register_uploaded_entities(
    job_id: str,
    entity_type: str,
    validation_file: str,
    token: str,
    group_uuid: str,
) -> JobResult:
    # Entity information should already be validated at this point
    upload = set_file_details(validation_file)
    fullpath = upload.get("fullpath")
    with open(fullpath, "r") as f:
        records = json.load(f)

    entities = convert_records(records, entity_type, group_uuid)

    percent_delta = 100 / len(entities)
    create_results = bulk_create_entities(
        entity_type,
        entities,
        token,
        after_each_callback=lambda idx: update_job_progress(percent_delta * (idx + 1)),
    )

    all_completed = all(v["success"] for v in create_results)

    # On success, we don't want to return the whole entity
    results = [
        {
            "uuid": v["data"].get("uuid") if v["success"] else None,
            "sennet_id": v["data"].get("sennet_id") if v["success"] else None,
            "index": idx + 1,  # this should correspond to the row number in the TSV
            "success": v["success"],
            "message": v["data"] if not v["success"] else "Success",
        }
        for idx, v in enumerate(create_results)
    ]
    return JobResult(success=all_completed, results=results)


def convert_records(records: list, entity_type: str, group_uuid: str) -> list:
    if equals(entity_type, Ontology.ops().entities().SOURCE):
        for item in records:
            item["lab_source_id"] = item["lab_id"]
            del item["lab_id"]
            item["protocol_url"] = item["selection_protocol"]
            del item["selection_protocol"]
            item["description"] = item["lab_notes"]
            del item["lab_notes"]
            item["group_uuid"] = group_uuid
        return records

    elif equals(entity_type, Ontology.ops().entities().SAMPLE):
        for item in records:
            item["direct_ancestor_uuid"] = item["ancestor_id"]
            del item["ancestor_id"]
            item["lab_tissue_sample_id"] = item["lab_id"]
            del item["lab_id"]
            item["description"] = item["lab_notes"]
            del item["lab_notes"]
            item["protocol_url"] = item["preparation_protocol"]
            del item["preparation_protocol"]
            item["organ"] = item["organ_type"]
            del item["organ_type"]
            if item["organ"] == "":
                del item["organ"]
            item["group_uuid"] = group_uuid
        return records
    else:
        return []
