import json
import logging
import urllib.request
from pathlib import Path
from typing import Union, Callable

import yaml
from flask import current_app
from hubmap_commons.schema_tools import check_json_matches_schema
from hubmap_sdk import Entity
from rule_engine import Context, EngineError, Rule

logger: logging.Logger = logging.getLogger(__name__)

SCHEMA_FILE = "rule_chain_schema.json"
SCHEMA_BASE_URI = "http://schemata.hubmapconsortium.org/"

rule_chain = None

# Have to translate pre-UBKG keys to UBKG keys
# Format is:
# "Key before UBKG integration": "UBKG Key"
pre_integration_to_ubkg_translation = {
    'vitessce-hints': 'vitessce_hints',
    'dir-schema': 'dir_schema',
    'tbl-schema': 'tbl_schema',
    'contains-pii': 'contains_full_genetic_sequences',
    'dataset-type': 'dataset_type',
    'is-multi-assay': 'is_multiassay',
    'pipeline-shorthand': 'pipeline_shorthand',
    'must-contain': 'must_contain',
}

# These are the keys returned by the rule chain before UBKG integration.
# We will return the UBKG data in this format as well for MVP.
# This is to avoid too much churn on end-users.
# We set primary manually so ignore it.
pre_integration_keys = [
    'assaytype',
    'vitessce-hints',
    'dir-schema',
    'tbl-schema',
    'contains-pii',
    # 'primary',
    'dataset-type',
    'description',
    'is-multi-assay',
    'pipeline-shorthand',
    'must-contain',
    "process_state"
]

pre_rule_chain = None
body_rule_chain = None
post_rule_chain = None


def initialize_rule_chains():
    """Initialize the rule chain from the source URI.

    Raises
    ------
    RuleSyntaxException
        If the JSON rules are not well-formed.
    """
    global pre_rule_chain, body_rule_chain, post_rule_chain
    rule_src_uri = current_app.config["RULE_CHAIN_URI"]
    try:
        rule_json = urllib.request.urlopen(rule_src_uri)
    except json.decoder.JSONDecodeError as excp:
        raise RuleSyntaxException(excp) from excp
    rule_chain_dict = RuleLoader(rule_json).load()
    pre_rule_chain = rule_chain_dict["pre"]
    body_rule_chain = rule_chain_dict["body"]
    post_rule_chain = rule_chain_dict["post"]


def calculate_assay_info(metadata: dict,
                         source_is_human: bool,
                         lookup_ubkg: Callable[[str], dict]
                         ) -> dict:
    """Calculate the assay information for the given metadata.

    Parameters
    ----------
    metadata : dict
        The metadata for the entity.

    Returns
    -------
    dict
        The assay information for the entity.
    """
    if any(elt is None
           for elt in [pre_rule_chain, body_rule_chain, post_rule_chain]):
        initialize_rule_chains()
    for key, value in metadata.items():
        if type(value) is str:
            if value.isdigit():
                metadata[key] = int(value)
    try:
        pre_values = pre_rule_chain.apply(metadata)
        body_values = body_rule_chain.apply(metadata, ctx=pre_values)
        assert "ubkg_code" in body_values, ("Rule matched but lacked ubkg_code:"
                                            f" {body_values}")
        ubkg_values = lookup_ubkg(body_values.get("ubkg_code", "NO_CODE")).get("value", {})
        rslt = post_rule_chain.apply(
            {},
            ctx={
                "source_is_human": source_is_human,
                "values": body_values,
                "ubkg_values": ubkg_values,
                "pre_values": pre_values,
                # "DEBUG": True
            }
        )
        return rslt
    except NoMatchException:
        return {}


def calculate_data_types(entity: Entity) -> list[str]:
    """Calculate the data types for the given entity.

    Parameters
    ----------
    entity : hubmap_sdk.Entity
        The entity

    Returns
    -------
    list[str]
        The data types for the entity.
    """
    data_types = [""]

    # Historically, we have used the data_types field. So check to make sure that
    # the data_types field is not empty and not a list of empty strings
    # If it has a value it must be an old derived dataset so use that to match the rules
    if (
            hasattr(entity, "data_types")
            and entity.data_types
            and set(entity.data_types) != {""}
    ):
        data_types = entity.data_types
    # Moving forward (2024) we are no longer using data_types for derived datasets.
    # Rather, we are going to use the dataset_info attribute which stores similar
    # information to match the rules. dataset_info is delimited by "__", so we can grab
    # the first item when splitting by that delimiter and pass that through to the
    # rules.
    elif hasattr(entity, "dataset_info") and entity.dataset_info:
        data_types = [entity.dataset_info.split("__")[0]]

    # Else case is covered by the initial data_types instantiation.
    return data_types


def build_entity_metadata(entity_json: dict) -> dict:
    """Build the metadata for the given entity.

    Parameters
    ----------
    entity_json : dict
        The entity

    Returns
    -------
    dict
        The metadata for the entity.
    """
    metadata = {}
    dag_prov_list = []
    if "ingest_metadata" in entity_json:
        # This if block should catch primary datasets because primary datasets should
        # have their metadata ingested as part of the reorganization.
        if "metadata" in entity_json and not isinstance(entity_json["metadata"], list):
            metadata = entity_json["metadata"]
        else:
            # If there is no ingest-metadata, then it must be a derived dataset
            metadata["data_types"] = calculate_data_types(entity_json)

        dag_prov_list = [
            elt['origin'] + ':' + elt['name']
            for elt in entity_json["ingest_metadata"].get('dag_provenance_list', [])
            if 'origin' in elt and 'name' in elt
        ]

        # In the case of Publications, we must also set the data_types.
        # The primary publication will always have metadata,
        # so we have to do the association here.
        if entity_json["entity_type"] == "Publication":
            metadata["data_types"] = calculate_data_types(entity_json)

    # If there is no ingest_metadata, then it must be a derived dataset
    else:
        metadata["data_types"] = calculate_data_types(entity_json)

    metadata["entity_type"] = entity_json["entity_type"]
    if metadata["entity_type"].upper() in ["DONOR", "SAMPLE"]:
        raise ValueError(f"Entity is a {metadata['entity_type']}")
    metadata["dag_provenance_list"] = dag_prov_list
    metadata["creation_action"] = entity_json.get("creation_action")

    return metadata


def get_data_from_ubkg(ubkg_code: str) -> dict:
    query = urllib.parse.urlencode({"application_context": current_app.config['APPLICATION_CONTEXT']})
    ubkg_api_url = f"{current_app.config['UBKG_SERVER']}assayclasses/{ubkg_code}?{query}"
    req = urllib.request.Request(ubkg_api_url)
    try:
        with urllib.request.urlopen(req) as response:
            response_data = response.read().decode("utf-8")
    except urllib.error.URLError as excp:
        print(f"Error getting extra info from UBKG {excp}")
        return {}

    return json.loads(response_data)


class NoMatchException(Exception):
    pass


class RuleLogicException(Exception):
    pass


class RuleSyntaxException(Exception):
    pass


class RuleLoader:
    def __init__(self, stream, format='yaml'):
        self.stream = stream
        assert format in ['yaml', 'json'], f"unknown format {format}"
        self.format = format
    def load(self):
        rule_chain_dict = {}
        if self.format == 'yaml':
            json_dict = yaml.safe_load(self.stream)
        elif self.format == 'json':
            if isinstance(self.stream, str):
                json_dict = json.loads(self.stream)
            else:
                json_dict = json.load(self.stream)
        else:
            raise RuntimeError(f"Unknown format {self.format} for input stream")
        check_json_matches_schema(json_dict,
                                  SCHEMA_FILE,
                                  str(Path(__file__).parent),
                                  SCHEMA_BASE_URI)
        for key in json_dict:
            rule_chain = RuleChain()
            json_recs = json_dict[key]
            for rec in json_recs:
                for rule in [rec[key2] for key2 in ['match', 'value']]:
                    assert Rule.is_valid(rule), f"Syntax error in rule string {rule}"
                try:
                    rule_cls = {'note': NoteRule,
                                'match': MatchRule}[rec['type'].lower()]
                    rule_chain.add(rule_cls(rec['match'], rec['value']))
                except KeyError:
                    raise RuleSyntaxException(f"Unknown rule type {rec['type']}")
            rule_chain_dict[key] = rule_chain
        return rule_chain_dict



class _RuleChainIter:
    def __init__(self, rule_chain):
        self.offset = 0
        self.rule_chain = rule_chain
    def __next__(self):
        if self.offset < len(self.rule_chain.links):
            rslt = self.rule_chain.links[self.offset]
            self.offset += 1
            return rslt
        else:
            raise StopIteration
    def __iter__(self):
        return self


class RuleChain:
    def __init__(self):
        self.links = []
    def add(self, link):
        self.links.append(link)
    def dump(self, ofile):
        ofile.write(f"START DUMP of {len(list(iter(self)))} rules\n")
        for idx, elt in enumerate(iter(self)):
            ofile.write(f"{idx}: {elt}\n")
        ofile.write(f"END DUMP of rules\n")
    def __iter__(self):
        return _RuleChainIter(self)
    @classmethod
    def cleanup(cls, val):
        """
        Convert val to JSON-appropriate data types
        """
        if isinstance(val, dict): # includes OrderedDict
            return dict({cls.cleanup(key): cls.cleanup(val[key]) for key in val})
        elif isinstance(val, list):
            return list(cls.cleanup(elt) for elt in val)
        else:
            return val
    def apply(self, rec, ctx = None):
        if ctx is None:
            ctx = {}  # so rules can leave notes for later rules
        for elt in iter(self):
            if ctx.get("DEBUG"):
                logger.debug(f"applying {elt} to rec:{rec}  ctx:{ctx}")
            rec_dict = rec | ctx;
            try:
                if elt.match_rule.matches(rec_dict):
                    val = elt.val_rule.evaluate(rec_dict)
                    if isinstance(elt, MatchRule):
                        return self.cleanup(val)
                    elif isinstance(elt, NoteRule):
                        assert isinstance(val, dict), f"Rule {elt} applied to {rec_dict} did not produce a dict"
                        ctx.update(val)
                    else:
                        raise NotImplementedError(f"Unknown rule type {type(elt)}")
            except EngineError as excp:
                logger.error(f"ENGINE_ERROR {type(excp)} {excp}")
                raise RuleLogicException(excp) from excp
            if ctx.get("DEBUG"):
                logger.debug("done")
        raise NoMatchException(f"No rule matched record {rec}")


class BaseRule:
    def __init__(self, rule_str, val_str):
        rule_ctx = Context(default_value=None)
        self.match_rule = Rule(rule_str, context=rule_ctx)
        self.val_rule = Rule(val_str, context=rule_ctx)


class MatchRule(BaseRule):
    def __str__(self):
        return f"<MatchRule({self.match_rule}, {self.val_rule})>"


class NoteRule(BaseRule):
    def __str__(self):
        return f"<NoteRule({self.match_rule}, {self.val_rule}>"
