import requests
from atlas_consortia_commons.string import equals
from flask import current_app
from hubmap_commons.file_helper import ensureTrailingSlashURL

from lib.file import ln_err
from lib.ontology import Ontology


def common_ln_errs(err: int, val: str) -> dict:
    if err == 1:
        return ln_err(f" `{val}` is a required field", 1)
    elif err == 2:
        return ln_err(f" `{val}` is not an accepted field", 1)
    elif err == 3:
        return ln_err(
            f"Unable to validate constraints. Entity Api returned the following: {val}"
        )
    elif err == 4:
        return ln_err(
            "This row has too few entries. Check file; verify spaces were not used where a tab should be",
            val,
        )
    elif err == 5:
        return ln_err("Failed to reach UUID Web Service", val)
    elif err == 6:
        return ln_err(
            "This row has too many entries. Check file; verify that there are only as many fields as there are headers",
            val,
        )
    elif err == 7:
        return ln_err("Unauthorized. Cannot access UUID-api", val)
    elif err == 8:
        return ln_err("Unable to verify `ancestor_id` exists", val)


def get_as_list(item):
    if type(item) is list:
        return item
    else:
        return [item]


def build_constraint(ancestor: dict, descendant: dict) -> dict:
    return {"ancestors": ancestor, "descendants": descendant}


def build_constraint_unit(entity: str, sub_type=None, sub_type_val=None) -> dict:
    constraint: dict = {
        "entity_type": entity,
        "sub_type": sub_type,
        "sub_type_val": sub_type_val,
    }
    return constraint


def append_constraints_list(
    entity_to_validate, ancestor_dict, header, entity_constraint_list, ancestor_id
):
    Entities = Ontology.ops().entities()
    ancestor_entity_type = ancestor_dict["type"].lower()
    url = (
        ensureTrailingSlashURL(current_app.config["ENTITY_WEBSERVICE_URL"])
        + "entities/"
        + ancestor_id
    )

    ancestor_result = requests.get(url, headers=header).json()
    sub_type = None
    sub_type_val = None
    if equals(ancestor_entity_type, Entities.DATASET):
        sub_type = get_as_list(ancestor_result["dataset_type"])

    if equals(ancestor_entity_type, Entities.SAMPLE):
        sub_type = get_as_list(ancestor_result["sample_category"])
        if equals(
            ancestor_result["sample_category"],
            Ontology.ops().specimen_categories().ORGAN,
        ):
            sub_type_val = get_as_list(ancestor_result["organ"])

    ancestor_to_validate = build_constraint_unit(
        ancestor_entity_type, sub_type, sub_type_val
    )

    dict_to_validate = build_constraint(ancestor_to_validate, entity_to_validate)
    entity_constraint_list.append(dict_to_validate)

    return entity_constraint_list
