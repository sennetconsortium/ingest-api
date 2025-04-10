import collections
import json
import logging
from flask import Blueprint, jsonify
from lib.services import get_token
from lib.ontology import Ontology
from lib.neo4j_helper import Neo4jHelper
from lib.rule_chain import (
    calculate_assay_info,
    get_data_from_ubkg
)
from hubmap_commons.hm_auth import AuthHelper

sankey_data_blueprint = Blueprint("sankey_data", __name__)
logger = logging.getLogger(__name__)


@sankey_data_blueprint.route("/datasets/sankey_data", methods=["GET"])
def get_ds_assaytype():
    # String constants
    HEADER_DATASET_GROUP_NAME = 'dataset_group_name'
    HEADER_ORGAN_TYPE = 'organ_type'
    HEADER_DATASET_TYPE_HIERARCHY = 'dataset_type_hierarchy'
    HEADER_DATASET_TYPE_DESCRIPTION = 'dataset_type_description'
    HEADER_DATASET_STATUS = 'dataset_status'
    ORGAN_TYPES = Ontology.ops(as_data_dict=True, data_as_val=True, val_key='rui_code').organ_types()
    HEADER_DATASET_SOURCE_TYPE = 'dataset_source_type'

    token: str = get_token()
    authorized = False
    if token:
        auth_helper_instance: AuthHelper = AuthHelper.instance()
        authorized = auth_helper_instance.has_read_privs(token)

    data_access_level = 'public' if authorized is False else None

    # Instantiation of the list dataset_prov_list
    dataset_sankey_list = []

    ####################################################################################################
    ## Neo4j query
    ####################################################################################################
    ds_predicate = ''
    organ_predicate = ''
    # We want to get primary datasets for this response
    creation_action = "{creation_action: 'Create Dataset Activity'}"

    if data_access_level:
        ds_predicate = "{status: 'Published'}"
        organ_predicate = f", data_access_level: '{data_access_level}'"

    query = (f"MATCH (ds:Dataset {ds_predicate})-[]->(a:Activity {creation_action})-[*]->(:Sample) "
             f"MATCH (source:Source)<-[:USED]-(oa)<-[:WAS_GENERATED_BY]-(organ:Sample {{sample_category:'{Ontology.ops().specimen_categories().ORGAN}'{organ_predicate}}})<-[*]-(ds) "
             f"WHERE NOT EXISTS((ds)<-[:REVISION_OF*]-(:Entity)) "  # We want to exclude previous revisions since we hide those on the portal search
             f"RETURN distinct ds.group_name, COLLECT(DISTINCT organ.organ), ds.dataset_type, ds.status, ds.uuid, ds.metadata, source.source_type order by ds.group_name")
    logger.info("======get_sankey_info() query======")
    logger.info(query)
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
            record_dict['dataset_group_name'] = record_contents[0]
            record_dict['organ_type'] = record_contents[1]
            record_dict['dataset_type'] = record_contents[2]
            record_dict['dataset_status'] = record_contents[3]
            record_dict['dataset_metadata'] = record_contents[5]
            record_dict['dataset_source_type'] = record_contents[6]
            list_of_dictionaries.append(record_dict)
        sankey_info = list_of_dictionaries
    ####################################################################################################
    ## Build response for sankey graph
    ####################################################################################################
    for dataset in sankey_info:
        internal_dict = collections.OrderedDict()
        internal_dict[HEADER_DATASET_GROUP_NAME] = dataset[HEADER_DATASET_GROUP_NAME]
        internal_dict[HEADER_DATASET_SOURCE_TYPE] = dataset[HEADER_DATASET_SOURCE_TYPE]
        is_human = dataset[HEADER_DATASET_SOURCE_TYPE].upper() == 'HUMAN'
        internal_dict[HEADER_ORGAN_TYPE] = []
        for organ_type in ORGAN_TYPES:
            for organ in dataset[HEADER_ORGAN_TYPE]:
                if ORGAN_TYPES[organ_type]['rui_code'] == organ:
                    internal_dict[HEADER_ORGAN_TYPE].append(ORGAN_TYPES[organ_type]['term'])
                    break

         # If the status is QA or Published then grab the 'modality' from UBKG
        # Otherwise just return dataset_type
        internal_dict[HEADER_DATASET_TYPE_HIERARCHY] = dataset['dataset_type']
        internal_dict[HEADER_DATASET_TYPE_DESCRIPTION] = dataset['dataset_type']
        try:
            if dataset['dataset_status'] in ['QA', 'Published'] and dataset['dataset_metadata']:
                rules_json = calculate_assay_info(json.loads(dataset['dataset_metadata']), is_human,
                                                  get_data_from_ubkg)

                if "assaytype" in rules_json:
                    desc = rules_json["description"]
                    assay_type = rules_json["assaytype"]

                    def prop_callback(d):
                        return d["assaytype"]

                    def val_callback(d):
                        return d["dataset_type"]["fig2"]["modality"]

                    assay_classes = Ontology.ops(prop_callback=prop_callback, val_callback=val_callback,
                                                 as_data_dict=True).assay_classes()
                    if assay_type in assay_classes:
                        internal_dict[HEADER_DATASET_TYPE_HIERARCHY] = assay_classes[assay_type]
                        internal_dict[HEADER_DATASET_TYPE_DESCRIPTION] = desc

        except Exception as e:
            logger.error(e)
            logger.error(dataset['dataset_type'])

        internal_dict[HEADER_DATASET_STATUS] = dataset['dataset_status']

        # Each dataset's dictionary is added to the list to be returned
        dataset_sankey_list.append(internal_dict)

    return jsonify(dataset_sankey_list)
