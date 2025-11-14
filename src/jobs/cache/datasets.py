import collections
import logging
import time
from datetime import timedelta
from threading import Thread
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
from lib.file import files_exist
from lib.neo4j_helper import Neo4jHelper
from lib.ontology import Ontology

logger = logging.getLogger(__name__)

DATASETS_DATASTATUS_JOB_ID = "update_datasets_datastatus"
DATASETS_DATASTATUS_JOB_PREFIX = "update_datasets_datastatus"
DATASETS_SANKEYDATA_JOB_PUBLIC_PREFIX = "update_dataset_sankey_data_public"
DATASETS_SANKEYDATA_JOB_CONSORTIUM_PREFIX = "update_dataset_sankey_data_consortium"


def schedule_update_datasets_datastatus(job_queue: JobQueue, delta: timedelta = timedelta(hours=1)):
    job_id = uuid4()
    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=update_datasets_datastatus,
        job_kwargs={},
        user={"id": DATASETS_DATASTATUS_JOB_PREFIX, "email": DATASETS_DATASTATUS_JOB_PREFIX},
        description="Update datasets datastatus",
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
            f"Failed to schedule update datasets datastatus job: {job_id}: {job.get_error()}"
        )


def run_query(neo4j_driver_instance, query, results, i):
    logger.info(query)
    try:
        with neo4j_driver_instance.session() as session:
            results[i] = session.run(query).data()
    except Exception as e:
        logger.error(e, exc_info=True)


def update_datasets_datastatus(schedule_next_job=True):
    try:
        logger.info("Starting update datasets datastatus")
        start = time.perf_counter()

        all_datasets_query = (
            "MATCH (ds:Dataset)-[:WAS_GENERATED_BY]->(a:Activity)-[:USED]->(ancestor) "
            "WHERE NOT (ds)<-[:REVISION_OF]-() "
            "RETURN ds.uuid AS uuid, ds.group_name AS group_name, ds.dataset_type AS dataset_type, "
            "ds.sennet_id AS sennet_id, ds.lab_dataset_id AS provider_experiment_id, ds.status AS status, "
            "ds.status_history AS status_history, "
            "ds.last_modified_timestamp AS last_touch, ds.published_timestamp AS published_timestamp, ds.created_timestamp AS created_timestamp, "
            "ds.data_access_level AS data_access_level, ds.assigned_to_group_name AS assigned_to_group_name, ds.ingest_task AS ingest_task, ds.error_message AS error_message, "
            "COLLECT(DISTINCT ds.uuid) AS datasets, COALESCE(ds.contributors IS NOT NULL AND ds.contributors <> '[]') AS has_contributors, "
            "COALESCE(ds.contacts IS NOT NULL AND ds.contacts <> '[]') AS has_contacts, ancestor.entity_type AS ancestor_entity_type, "
            "a.creation_action AS activity_creation_action"
        )

        organ_query = (
            "MATCH (ds:Dataset)-[*]->(o:Sample {sample_category: 'Organ'}) "
            "WHERE (ds)-[:WAS_GENERATED_BY]->(:Activity) "
            "RETURN DISTINCT ds.uuid AS uuid, o.organ AS organ, o.sennet_id as organ_sennet_id, o.uuid as organ_uuid "
        )

        source_query = (
            "MATCH (ds:Dataset)-[*]->(dn:Source) "
            "WHERE (ds)-[:WAS_GENERATED_BY]->(:Activity) "
            "RETURN DISTINCT ds.uuid AS uuid, "
            "COLLECT(DISTINCT dn.sennet_id) AS source_sennet_id, "
            "COLLECT(DISTINCT dn.source_type) AS source_type, "
            "COLLECT(DISTINCT dn.lab_source_id) AS source_lab_id, COALESCE(dn.metadata IS NOT NULL AND dn.metadata <> '{}') AS has_donor_metadata"
        )

        processed_datasets_query = (
            "MATCH (s:Entity)-[:WAS_GENERATED_BY]->(a:Activity)-[:USED]->(ds:Dataset) WHERE "
            "a.creation_action in ['Central Process', 'Lab Process'] "
            "RETURN DISTINCT ds.uuid AS uuid, COLLECT(DISTINCT {uuid: s.uuid, sennet_id: s.sennet_id, status: s.status, created_timestamp: s.created_timestamp, "
            "data_access_level: s.data_access_level, group_name: s.group_name}) AS processed_datasets"
        )

        upload_query = (
            "MATCH (u:Upload)<-[:IN_UPLOAD]-(ds) "
            "RETURN DISTINCT ds.uuid AS uuid, COLLECT(DISTINCT u.sennet_id) AS upload"
        )

        has_rui_query = (
            "MATCH (ds:Dataset)-[:USED|WAS_GENERATED_BY*]->(s:Sample) "
            "RETURN ds.uuid AS uuid, COLLECT( "
            "CASE "
            "WHEN s.rui_exemption = true THEN 'Exempt' "
            "WHEN s.rui_location IS NOT NULL AND NOT TRIM(s.rui_location) = '' THEN 'True' "
            "ELSE 'False' "
            "END) as has_rui_info"
        )

        # check for metadata in direct ancestor samples (primary datasets only)
        has_source_sample_metadata_query = (
            "MATCH (ds:Dataset)-[:WAS_GENERATED_BY]->(a:Activity)-[:USED]->(s:Sample) "
            "WHERE TOLOWER(a.creation_action) = 'create dataset activity' "
            "RETURN ds.uuid AS uuid, "
            "COLLECT( "
            "CASE "
            "WHEN s.metadata IS NOT NULL AND NOT TRIM(s.metadata) = '' THEN 'True' "
            "ELSE 'False' "
            "END) AS has_source_sample_metadata"
        )

        blocks_ancestors_query = (
            "MATCH (ds:Dataset)-[:USED|WAS_GENERATED_BY*]->(s:Sample) "
            "WHERE s.sample_category = 'Block' RETURN ds.uuid as uuid, COLLECT(DISTINCT {uuid: s.uuid, sennet_id: s.sennet_id}) as block_ancestors  "
        )

        direct_ancestors_query = (
            "MATCH (ancestor:Entity)<-[:USED]-(:Activity)<-[:WAS_GENERATED_BY]-(ds:Dataset) "
            "RETURN ds.uuid as uuid, COLLECT(DISTINCT {uuid: ancestor.uuid, sennet_id: ancestor.sennet_id}) as direct_ancestors  "
        )

        descendant_qa_query = (
            "MATCH (ds:Dataset)<-[:USED]-(a:Activity)<-[:WAS_GENERATED_BY]-(e:Dataset) "
            "WHERE e.status IN ['QA'] AND TOLOWER(a.creation_action) = 'central process' "
            "RETURN ds.uuid as uuid"
        )

        descendant_published_query = (
            "MATCH (ds:Dataset)<-[:USED]-(a:Activity)<-[:WAS_GENERATED_BY]-(e:Dataset) "
            "WHERE e.status IN ['Published'] AND TOLOWER(a.creation_action) = 'central process' "
            "RETURN ds.uuid as uuid"
        )

        displayed_fields = [
            "sennet_id",
            "group_name",
            "status",
            "organ",
            "provider_experiment_id",
            "last_touch",
            "has_contacts",
            "has_contributors",
            "dataset_type",
            "source_sennet_id",
            "source_lab_id",
            "has_dataset_metadata",
            "has_donor_metadata",
            "upload",
            "has_rui_info",
            "globus_url",
            "has_data",
            "organ_sennet_id",
            "assigned_to_group_name",
            "ingest_task",
            "error_message",
        ]

        queries = [
            all_datasets_query,
            organ_query,
            source_query,
            processed_datasets_query,
            upload_query,
            has_rui_query,
            has_source_sample_metadata_query,
            blocks_ancestors_query,
            direct_ancestors_query,
            descendant_qa_query,
            descendant_published_query,
        ]
        results = [None] * len(queries)
        threads = []
        for i, query in enumerate(queries):
            thread = Thread(target=run_query, args=(Neo4jHelper.get_instance(), query, results, i))
            thread.name = query
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        current_job = get_current_job()
        if current_job is not None:
            update_job_progress(50, current_job)

        output_dict = {}
        # Here we specifically indexed the values in 'results' in case certain threads completed out of order
        all_datasets_result = results[0]
        organ_result = results[1]
        source_result = results[2]
        processed_datasets_result = results[3]
        upload_result = results[4]
        has_rui_result = results[5]
        has_source_sample_metadata_result = results[6]
        blocks_ancestors_result = results[7]
        direct_ancestors_result = results[8]
        descendant_qa_result = results[9]
        descendant_published_result = results[10]

        for dataset in all_datasets_result:
            output_dict[dataset["uuid"]] = dataset
            output_dict[dataset["uuid"]]["has_qa_processed"] = False
            output_dict[dataset["uuid"]]["has_published_processed"] = False

        for dataset in organ_result:
            if output_dict.get(dataset["uuid"]):
                output_dict[dataset["uuid"]]["organ"] = dataset["organ"]
                output_dict[dataset["uuid"]]["organ_sennet_id"] = dataset["organ_sennet_id"]
                output_dict[dataset["uuid"]]["organ_uuid"] = dataset["organ_uuid"]

        for dataset in source_result:
            if output_dict.get(dataset["uuid"]):
                output_dict[dataset["uuid"]]["source_sennet_id"] = dataset["source_sennet_id"]
                output_dict[dataset["uuid"]]["source_type"] = dataset["source_type"]
                output_dict[dataset["uuid"]]["source_lab_id"] = dataset["source_lab_id"]
                output_dict[dataset["uuid"]]["has_donor_metadata"] = dataset["has_donor_metadata"]

        for dataset in processed_datasets_result:
            if output_dict.get(dataset["uuid"]):
                output_dict[dataset["uuid"]]["processed_datasets"] = dataset["processed_datasets"]

        for dataset in upload_result:
            if output_dict.get(dataset["uuid"]):
                output_dict[dataset["uuid"]]["upload"] = dataset["upload"]

        for dataset in has_rui_result:
            has_rui = str(False)
            if output_dict.get(dataset["uuid"]):
                if "True" in dataset["has_rui_info"]:
                    has_rui = str(True)
                elif "Exempt" in dataset["has_rui_info"]:
                    has_rui = "Exempt"
                output_dict[dataset["uuid"]]["has_rui_info"] = has_rui

        for dataset in has_source_sample_metadata_result:
            if dataset["uuid"] in output_dict:
                output_dict[dataset["uuid"]]["has_source_sample_metadata"] = str(
                    "True" in dataset["has_source_sample_metadata"]
                )

        for dataset in blocks_ancestors_result:
            if output_dict.get(dataset["uuid"]):
                output_dict[dataset["uuid"]]["blocks"] = dataset["block_ancestors"]

        for dataset in direct_ancestors_result:
            if output_dict.get(dataset["uuid"]):
                output_dict[dataset["uuid"]]["parent_ancestors"] = dataset["direct_ancestors"]

        for dataset in descendant_published_result:
            if output_dict.get(dataset["uuid"]):
                output_dict[dataset["uuid"]]["has_published_processed"] = True

        for dataset in descendant_qa_result:
            if output_dict.get(dataset["uuid"]):
                output_dict[dataset["uuid"]]["has_qa_processed"] = True

        combined_results = list(output_dict.values())
        if current_job is not None:
            update_job_progress(75, current_job)

        organ_types_dict = Ontology.ops(
            as_data_dict=True, key="organ_uberon", val_key="term", prop_callback=None
        ).organ_types()
        for dataset in combined_results:
            globus_url = get_globus_url(
                dataset.get("data_access_level"), dataset.get("group_name"), dataset.get("uuid")
            )
            dataset["globus_url"] = globus_url

            dataset["last_touch"] = (
                dataset["last_touch"]
                if dataset["published_timestamp"] is None
                else dataset["published_timestamp"]
            )
            dataset["is_primary"] = (
                "True"
                if dataset.pop("activity_creation_action").lower() == "create dataset activity"
                else "False"
            )

            has_data = files_exist(
                dataset.get("uuid"), dataset.get("data_access_level"), dataset.get("group_name")
            )
            has_dataset_metadata = files_exist(
                dataset.get("uuid"),
                dataset.get("data_access_level"),
                dataset.get("group_name"),
                metadata=True,
            )
            dataset["has_data"] = has_data
            dataset["has_dataset_metadata"] = has_dataset_metadata

            for prop in dataset:
                if isinstance(dataset[prop], list) and prop not in [
                    "processed_datasets",
                    "blocks",
                    "parent_ancestors",
                ]:
                    dataset[prop] = ", ".join(dataset[prop])

                if isinstance(dataset[prop], (bool)):
                    dataset[prop] = str(dataset[prop])

                if (
                    isinstance(dataset[prop], str)
                    and len(dataset[prop]) >= 2
                    and dataset[prop][0] == "["
                    and dataset[prop][-1] == "]"
                ):
                    # For cases like `"ingest_task": "[Empty directory]"` we should not
                    # convert to a list. Converting will cause a ValueError. Leave it
                    # as the original value and move on
                    try:
                        prop_as_list = string_helper.convert_str_literal(dataset[prop])
                        if len(prop_as_list) > 0:
                            dataset[prop] = prop_as_list
                        else:
                            dataset[prop] = ""
                    except ValueError:
                        pass

                if dataset[prop] is None:
                    dataset[prop] = ""

                if prop == "processed_datasets":
                    for processed in dataset["processed_datasets"]:
                        processed["globus_url"] = get_globus_url(
                            processed.get("data_access_level"),
                            processed.get("group_name"),
                            processed.get("uuid"),
                        )

            for field in displayed_fields:
                if dataset.get(field) is None:
                    dataset[field] = ""

            if (
                # Check for Adipose Tissue (UBERON:0001013), Blood (UBERON:0000178), Bone Marrow (UBERON:0002371), Bone (UBERON:0001474), Muscle (UBERON:0005090), and Other (UBERON:0010000)
                dataset.get("organ")
                and dataset["organ"].upper()
                in [
                    "UBERON:0001013",
                    "UBERON:0000178",
                    "UBERON:0002371",
                    "UBERON:0001474",
                    "UBERON:0005090",
                    "UBERON:0010000",
                ]
            ) or (
                dataset.get("source_type")
                and dataset["source_type"].upper() in ["MOUSE", "MOUSE ORGANOID"]
            ):
                dataset["has_rui_info"] = "not-applicable"

            if dataset.get("organ") and dataset.get("organ") in organ_types_dict:
                dataset["organ"] = organ_types_dict[dataset["organ"]]

        if current_job is not None:
            update_job_progress(100, current_job)

        logger.info(
            f"Finished updating datasets datastatus in {time.perf_counter() - start:.2f} seconds"
        )

        return JobResult(
            success=True,
            results={"data": combined_results, "last_updated": int(time.time() * 1000)},
        )

    except Exception as e:
        logger.error(f"Failed to update datasets datastatus: {e}", exc_info=True)
        raise e

    finally:
        if schedule_next_job:
            # Schedule the next cache job
            connection = get_current_connection()
            job_queue = JobQueue(connection)
            schedule_update_datasets_datastatus(job_queue)


def schedule_update_dataset_sankey_data(
    job_queue: JobQueue,
    delta: timedelta = timedelta(hours=1),
    authorized=False,
    dataset_type_hierarchy: str = None,
):
    job_id = uuid4()
    id_email = DATASETS_SANKEYDATA_JOB_PUBLIC_PREFIX
    if authorized:
        id_email = DATASETS_SANKEYDATA_JOB_CONSORTIUM_PREFIX

    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=update_dataset_sankey_data,
        job_kwargs={"authorized": authorized, "dataset_type_hierarchy": dataset_type_hierarchy},
        user={"id": id_email, "email": id_email},
        description="Update datasets sankey data",
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
            f"Failed to schedule update datasets sankey data job: {job_id}: {job.get_error()}"
        )


def update_dataset_sankey_data(
    authorized=False, dataset_type_hierarchy=None, schedule_next_job=True
):
    try:
        logger.info("Starting update datasets sankey data")
        start = time.perf_counter()

        # String constants
        HEADER_DATASET_GROUP_NAME = "dataset_group_name"
        HEADER_ORGAN_TYPE = "organ_type"
        HEADER_DATASET_TYPE_HIERARCHY = "dataset_type_hierarchy"
        HEADER_DATASET_TYPE_DESCRIPTION = "dataset_type_description"
        HEADER_DATASET_STATUS = "dataset_status"
        ORGAN_TYPES = Ontology.ops(
            as_data_dict=True, data_as_val=True, val_key="organ_uberon", prop_callback=None
        ).organ_types()
        HEADER_DATASET_SOURCE_TYPE = "dataset_source_type"

        data_access_level = "public" if authorized is False else None

        # Instantiation of the list dataset_prov_list
        dataset_sankey_list = []

        ####################################################################################################
        ## Neo4j query
        ####################################################################################################
        ds_predicate = ""
        organ_predicate = ""
        # We want to get primary datasets for this response
        creation_action = "{creation_action: 'Create Dataset Activity'}"

        if data_access_level:
            ds_predicate = "{status: 'Published'}"
            organ_predicate = f", data_access_level: '{data_access_level}'"

        query = (
            f"MATCH (ds:Dataset {ds_predicate})-[]->(a:Activity {creation_action})-[*]->(:Sample) "
            f"MATCH (source:Source)<-[:USED]-(oa)<-[:WAS_GENERATED_BY]-(organ:Sample {{sample_category:'{Ontology.ops().specimen_categories().ORGAN}'{organ_predicate}}})<-[*]-(ds) "
            f"WHERE NOT EXISTS((ds)<-[:REVISION_OF*]-(:Entity)) "  # We want to exclude previous revisions since we hide those on the portal search
            f"RETURN distinct ds.group_name, COLLECT(DISTINCT organ.organ), ds.dataset_type, ds.status, ds.uuid, ds.metadata, source.source_type order by ds.group_name"
        )
        with Neo4jHelper.get_instance().session() as session:
            result = session.run(query)
            list_of_dictionaries = []
            for record in result:
                record_dict = {}
                record_contents = []
                # Individual items within a record are non subscriptable. By putting then in a small list, we can address
                # Each item in a record.
                for item in record:
                    record_contents.append(item)
                record_dict["dataset_group_name"] = record_contents[0]
                record_dict["organ_type"] = record_contents[1]
                record_dict["dataset_type"] = record_contents[2]
                record_dict["dataset_status"] = record_contents[3]
                record_dict["dataset_metadata"] = record_contents[5]
                record_dict["dataset_source_type"] = record_contents[6]
                list_of_dictionaries.append(record_dict)
            sankey_info = list_of_dictionaries
        ####################################################################################################
        ## Build response for sankey graph
        ####################################################################################################

        current_job = get_current_job()
        percent_delta = 100 / len(sankey_info) if sankey_info else 100

        for index, dataset in enumerate(sankey_info):
            internal_dict = collections.OrderedDict()
            internal_dict[HEADER_DATASET_GROUP_NAME] = dataset[HEADER_DATASET_GROUP_NAME]
            internal_dict[HEADER_DATASET_SOURCE_TYPE] = dataset[HEADER_DATASET_SOURCE_TYPE]
            is_human = dataset[HEADER_DATASET_SOURCE_TYPE].upper() == "HUMAN"
            internal_dict[HEADER_ORGAN_TYPE] = []
            for organ_type in ORGAN_TYPES:
                for organ in dataset[HEADER_ORGAN_TYPE]:
                    if ORGAN_TYPES[organ_type]["organ_uberon"] == organ:
                        internal_dict[HEADER_ORGAN_TYPE].append(ORGAN_TYPES[organ_type]["term"])
                        break

            # Grab the modality from UBKG
            internal_dict[HEADER_DATASET_TYPE_HIERARCHY] = dataset["dataset_type"]
            internal_dict[HEADER_DATASET_TYPE_DESCRIPTION] = None
            try:
                if dataset_type_hierarchy and dataset["dataset_type"] in dataset_type_hierarchy:
                    internal_dict[HEADER_DATASET_TYPE_HIERARCHY] = dataset_type_hierarchy[
                        dataset["dataset_type"]
                    ]
                    internal_dict[HEADER_DATASET_TYPE_DESCRIPTION] = dataset["dataset_type"]

            except Exception as e:
                logger.error(e)
                logger.error(dataset["dataset_type"])

            internal_dict[HEADER_DATASET_STATUS] = dataset["dataset_status"]

            # Each dataset's dictionary is added to the list to be returned
            dataset_sankey_list.append(internal_dict)
            if current_job is not None:
                update_job_progress(percent_delta * (index + 1), current_job)

        if current_job is not None:
            update_job_progress(100, current_job)

        logger.info(
            f"Finished updating datasets sankey data in {time.perf_counter() - start:.2f} seconds"
        )

        return JobResult(
            success=True,
            results={"data": dataset_sankey_list, "last_updated": int(time.time() * 1000)},
        )
    except Exception as e:
        logger.error(f"Failed to update datasets sankey data: {e}", exc_info=True)
        raise e
    finally:
        if schedule_next_job:
            # Schedule the next cache job
            connection = get_current_connection()
            job_queue = JobQueue(connection)
            schedule_update_dataset_sankey_data(
                job_queue=job_queue,
                authorized=authorized,
                dataset_type_hierarchy=dataset_type_hierarchy,
            )
