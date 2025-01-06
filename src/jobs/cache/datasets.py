import logging
import time
from datetime import timedelta
from threading import Thread
from typing import Optional
from uuid import uuid4

from flask import current_app
from hubmap_commons import neo4j_driver, string_helper
from rq import get_current_connection

from jobs import JobQueue, JobResult, JobStatus, JobVisibility, SERVER_PROCESS_ID
from lib import get_globus_url
from lib.dataset_helper import DatasetHelper
from lib.file import files_exist
from lib.ontology import Ontology

logger = logging.getLogger(__name__)


def schedule_update_datasets_datastatus(job_queue: JobQueue, delta: Optional[timedelta] = timedelta(hours=1)):
    job_id = f'update_datasets_datastatus:{uuid4()}'
    job = job_queue.enqueue_job(
        job_id=job_id,
        job_func=update_datasets_datastatus,
        job_kwargs={},
        user={'id': SERVER_PROCESS_ID, 'email': SERVER_PROCESS_ID},
        description='Update datasets datastatus',
        metadata={},
        visibility=JobVisibility.PRIVATE,
        at_datetime=delta
    )

    status = job.get_status()
    if status == JobStatus.FAILED:
        logger.error(f'Failed to schedule update datasets datastatus job: {job_id}: {job.get_error()}')


def run_query(neo4j_driver_instance, query, results, i):
    logger.info(query)
    try:
        with neo4j_driver_instance.session() as session:
            results[i] = session.run(query).data()
    except Exception as e:
        logger.error(e, exc_info=True)


def update_datasets_datastatus():
    try:
        logger.info("Starting update datasets datastatus")
        start = time.perf_counter()
        neo4j_driver_instance = neo4j_driver.instance(current_app.config['NEO4J_SERVER'],
                                                      current_app.config['NEO4J_USERNAME'],
                                                      current_app.config['NEO4J_PASSWORD'])
        all_datasets_query = (
            "MATCH (ds:Dataset)-[:WAS_GENERATED_BY]->(:Activity)-[:USED]->(ancestor) "
            "RETURN ds.uuid AS uuid, ds.group_name AS group_name, ds.dataset_type AS dataset_type, "
            "ds.sennet_id AS sennet_id, ds.lab_dataset_id AS provider_experiment_id, ds.status AS status, "
            "ds.last_modified_timestamp AS last_touch, ds.published_timestamp AS published_timestamp, ds.created_timestamp AS created_timestamp, ds.data_access_level AS data_access_level, "
            "ds.assigned_to_group_name AS assigned_to_group_name, ds.ingest_task AS ingest_task, COLLECT(DISTINCT ds.uuid) AS datasets, "
            "COALESCE(ds.contributors IS NOT NULL AND ds.contributors <> '[]') AS has_contributors, COALESCE(ds.contacts IS NOT NULL AND ds.contacts <> '[]') AS has_contacts, "
            "ancestor.entity_type AS ancestor_entity_type"
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
            "a.creation_action in ['Central Process', 'Lab Process'] RETURN DISTINCT ds.uuid AS uuid, COLLECT(DISTINCT {uuid: s.uuid, sennet_id: s.sennet_id, status: s.status, created_timestamp: s.created_timestamp, data_access_level: s.data_access_level, group_name: s.group_name}) AS processed_datasets"
        )

        upload_query = (
            "MATCH (u:Upload)<-[:IN_UPLOAD]-(ds) "
            "RETURN DISTINCT ds.uuid AS uuid, COLLECT(DISTINCT u.sennet_id) AS upload"
        )

        has_rui_query = (
            "MATCH (ds:Dataset) "
            "WHERE (ds)-[:WAS_GENERATED_BY]->(:Activity) "
            "WITH ds, [(ds)-[*]->(s:Sample) | s.rui_location] AS rui_locations "
            "RETURN ds.uuid AS uuid, any(rui_location IN rui_locations WHERE rui_location IS NOT NULL) AS has_rui_info"
        )

        displayed_fields = [
            "sennet_id", "group_name", "status", "organ", "provider_experiment_id", "last_touch", "has_contacts",
            "has_contributors", "dataset_type", "source_sennet_id", "source_lab_id",
            "has_dataset_metadata", "has_donor_metadata", "upload", "has_rui_info", "globus_url",
            "has_data", "organ_sennet_id", "assigned_to_group_name", "ingest_task",
        ]

        queries = [all_datasets_query, organ_query, source_query, processed_datasets_query, upload_query, has_rui_query]
        results = [None] * len(queries)
        threads = []
        for i, query in enumerate(queries):
            thread = Thread(target=run_query, args=(neo4j_driver_instance, query, results, i))
            thread.name = query
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

        output_dict = {}
        # Here we specifically indexed the values in 'results' in case certain threads completed out of order
        all_datasets_result = results[0]
        organ_result = results[1]
        source_result = results[2]
        processed_datasets_result = results[3]
        upload_result = results[4]
        has_rui_result = results[5]

        for dataset in all_datasets_result:
            output_dict[dataset['uuid']] = dataset
        for dataset in organ_result:
            if output_dict.get(dataset['uuid']):
                output_dict[dataset['uuid']]['organ'] = dataset['organ']
                output_dict[dataset['uuid']]['organ_sennet_id'] = dataset['organ_sennet_id']
                output_dict[dataset['uuid']]['organ_uuid'] = dataset['organ_uuid']
        for dataset in source_result:
            if output_dict.get(dataset['uuid']):
                output_dict[dataset['uuid']]['source_sennet_id'] = dataset['source_sennet_id']
                output_dict[dataset['uuid']]['source_type'] = dataset['source_type']
                # output_dict[dataset['uuid']]['source_submission_id'] = dataset['source_submission_id']
                output_dict[dataset['uuid']]['source_lab_id'] = dataset['source_lab_id']
                output_dict[dataset['uuid']]['has_donor_metadata'] = dataset['has_donor_metadata']
        for dataset in processed_datasets_result:
            if output_dict.get(dataset['uuid']):
                output_dict[dataset['uuid']]['processed_datasets'] = dataset['processed_datasets']
        for dataset in upload_result:
            if output_dict.get(dataset['uuid']):
                output_dict[dataset['uuid']]['upload'] = dataset['upload']
        for dataset in has_rui_result:
            if output_dict.get(dataset['uuid']):
                output_dict[dataset['uuid']]['has_rui_info'] = dataset['has_rui_info']

        combined_results = []
        for uuid in output_dict:
            combined_results.append(output_dict[uuid])

        dataset_helper = DatasetHelper(current_app.config)
        for dataset in combined_results:
            globus_url = get_globus_url(dataset.get('data_access_level'), dataset.get('group_name'),
                                        dataset.get('uuid'))
            dataset['globus_url'] = globus_url

            dataset['last_touch'] = dataset['last_touch'] if dataset['published_timestamp'] is None else dataset['published_timestamp']
            dataset['is_primary'] = dataset_helper.dataset_is_primary(dataset.get('uuid'))

            has_data = files_exist(dataset.get('uuid'), dataset.get('data_access_level'), dataset.get('group_name'))
            has_dataset_metadata = files_exist(dataset.get('uuid'),
                                               dataset.get('data_access_level'),
                                               dataset.get('group_name'),
                                               metadata=True)
            dataset['has_data'] = has_data
            dataset['has_dataset_metadata'] = has_dataset_metadata

            for prop in dataset:
                if isinstance(dataset[prop], list) and prop != 'processed_datasets':
                    dataset[prop] = ", ".join(dataset[prop])

                if isinstance(dataset[prop], (bool)):
                    dataset[prop] = str(dataset[prop])

                if (
                    isinstance(dataset[prop], str)
                    and len(dataset[prop]) >= 2
                    and dataset[prop][0] == "[" and dataset[prop][-1] == "]"
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

                if prop == 'processed_datasets':
                    for processed in dataset['processed_datasets']:
                        processed['globus_url'] = get_globus_url(processed.get('data_access_level'),
                                                                 processed.get('group_name'),
                                                                 processed.get('uuid'))

            for field in displayed_fields:
                if dataset.get(field) is None:
                    dataset[field] = ""

            if (dataset.get('organ') and dataset['organ'].upper() in ['AD', 'BD', 'BM', 'BS', 'MU', 'OT']) or (
                    dataset.get('source_type') and dataset['source_type'].upper() in ['MOUSE', 'MOUSE ORGANOID']):
                dataset['has_rui_info'] = "not-applicable"

            organ_types_dict = Ontology.ops(as_data_dict=True, key='rui_code', val_key='term').organ_types()
            if dataset.get('organ') and dataset.get('organ') in organ_types_dict:
                dataset['organ'] = organ_types_dict[dataset['organ']]

        logger.info(f"Finished updating datasets datastatus in {time.perf_counter() - start:.2f} seconds")

        return JobResult(success=True, results={
            'data': combined_results,
            'last_updated': int(time.time() * 1000)
        })

    except Exception as e:
        logger.error(f"Failed to update datasets datastatus: {e}", exc_info=True)
        raise e
    finally:
        # Schedule the next cache job
        connection = get_current_connection()
        job_queue = JobQueue(connection)
        schedule_update_datasets_datastatus(job_queue)
