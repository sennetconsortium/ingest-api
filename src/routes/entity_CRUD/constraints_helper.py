
def get_as_list(item):
    if type(item) is list:
        return item
    else:
        return [item]


def build_constraint(ancestor: dict, descendant: dict) -> dict:
    return {
        'ancestors': ancestor,
        'descendants': descendant
    }


def build_constraint_unit(entity: str, sub_type=None, sub_type_val=None) -> dict:
    constraint: dict = {
        'entity_type': entity,
        'sub_type': sub_type,
        'sub_type_val': sub_type_val
    }
    return constraint