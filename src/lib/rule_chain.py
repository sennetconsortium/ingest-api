import json
import logging
import urllib.request
from pathlib import Path
from typing import Union

import yaml
from flask import current_app
from hubmap_commons.schema_tools import check_json_matches_schema
from hubmap_sdk import Entity
from rule_engine import Context, EngineError, Rule

logger: logging.Logger = logging.getLogger(__name__)

SCHEMA_FILE = "rule_chain_schema.json"
SCHEMA_BASE_URI = "http://schemata.hubmapconsortium.org/"


rule_chain = None


def initialize_rule_chain():
    """Initialize the rule chain from the source URI.

    Raises
    ------
    RuleSyntaxException
        If the JSON rules are not well-formed.
    """
    global rule_chain
    rule_src_uri = current_app.config["RULE_CHAIN_URI"]
    try:
        json_rules = urllib.request.urlopen(rule_src_uri)
    except json.decoder.JSONDecodeError as excp:
        raise RuleSyntaxException(excp) from excp
    rule_chain = RuleLoader(json_rules).load()


def calculate_assay_info(metadata: dict) -> dict:
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
    if not rule_chain:
        initialize_rule_chain()
    for key, value in metadata.items():
        if type(value) is str:
            if value.isdigit():
                metadata[key] = int(value)
    rslt = rule_chain.apply(metadata)
    # TODO: check that rslt has the expected parts
    return rslt


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


def build_entity_metadata(entity: Union[Entity, dict]) -> dict:
    """Build the metadata for the given entity.

    Parameters
    ----------
    entity : Union[hubmap_sdk.Entity, dict]
        The entity

    Returns
    -------
    dict
        The metadata for the entity.
    """
    if isinstance(entity, dict):
        entity = Entity(entity)

    metadata = {}
    dag_prov_list = []
    if hasattr(entity, "ingest_metadata"):
        # This if block should catch primary datasets because primary datasets should
        # their metadata ingested as part of the reorganization.
        if "metadata" in entity.ingest_metadata:
            metadata = entity.ingest_metadata["metadata"]
        else:
            # If there is no ingest-metadata, then it must be a derived dataset
            metadata["data_types"] = calculate_data_types(entity)

        dag_prov_list = [elt['origin'] + ':' + elt['name']
                         for elt in entity.ingest_metadata.get('dag_provenance_list',
                                                               [])
                         if 'origin' in elt and 'name' in elt
                         ]

        # In the case of Publications, we must also set the data_types.
        # The primary publication will always have metadata,
        # so we have to do the association here.
        if entity.entity_type == "Publication":
            metadata["data_types"] = calculate_data_types(entity)

    # If there is no metadata, then it must be a derived dataset
    else:
        metadata["data_types"] = calculate_data_types(entity)

    metadata["entity_type"] = entity.entity_type
    metadata["dag_provenance_list"] = dag_prov_list
    metadata["creation_action"] = entity.creation_action

    return metadata


class NoMatchException(Exception):
    pass


class RuleLogicException(Exception):
    pass


class RuleSyntaxException(Exception):
    pass


class RuleLoader:
    def __init__(self, stream, format="yaml"):
        self.stream = stream
        assert format in ["yaml", "json"], f"unknown format {format}"
        self.format = format

    def load(self):
        rule_chain = RuleChain()
        if self.format == "yaml":
            json_recs = yaml.safe_load(self.stream)
        elif self.format == "json":
            if isinstance(self.stream, str):
                json_recs = json.loads(self.stream)
            else:
                json_recs = json.load(self.stream)
        else:
            raise RuntimeError(f"Unknown format {self.format} for input stream")
        check_json_matches_schema(
            json_recs, SCHEMA_FILE, str(Path(__file__).parent), SCHEMA_BASE_URI
        )
        for rec in json_recs:
            for rule in [rec[key] for key in ["match", "value"]]:
                assert Rule.is_valid(rule), f"Syntax error in rule string {rule}"
            try:
                rule_cls = {"note": NoteRule, "match": MatchRule}[rec["type"].lower()]
            except KeyError:
                raise RuleSyntaxException(f"Unknown rule type {rec['type']}")
            rule_chain.add(rule_cls(rec["match"], rec["value"]))
        return rule_chain


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
        print(f"START DUMP of {len(list(iter(self)))} rules")
        for idx, elt in enumerate(iter(self)):
            print(f"{idx}: {elt}")
        print("END DUMP of rules")

    def __iter__(self):
        return _RuleChainIter(self)

    @classmethod
    def cleanup(cls, val):
        """
        Convert val to JSON-appropriate data types
        """
        if isinstance(val, dict):  # includes OrderedDict
            return dict({cls.cleanup(key): cls.cleanup(val[key]) for key in val})
        elif isinstance(val, list):
            return list(cls.cleanup(elt) for elt in val)
        else:
            return val

    def apply(self, rec):
        ctx = {}  # so rules can leave notes for later rules
        for elt in iter(self):
            rec_dict = rec | ctx
            try:
                if elt.match_rule.matches(rec_dict):
                    val = elt.val_rule.evaluate(rec_dict)
                    if isinstance(elt, MatchRule):
                        return self.cleanup(val)
                    elif isinstance(elt, NoteRule):
                        assert isinstance(
                            val, dict
                        ), f"Rule {elt} applied to {rec_dict} did not produce a dict"
                        ctx.update(val)
                    else:
                        raise NotImplementedError(f"Unknown rule type {type(elt)}")
            except EngineError as excp:
                print(f"ENGINE_ERROR {type(excp)} {excp}")
                raise RuleLogicException(excp) from excp
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
