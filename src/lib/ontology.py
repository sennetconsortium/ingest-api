# TODO: Pull these terms from the ontology-api when ready. Auto generate constants via the api. This lib is also within entity-api.
from atlas_consortia_commons.object import build_enum_class
from flask import current_app


def enum_val(e):
    return e.value

def entities():
    #TODO use when resolved in api
    response = current_app.ubkg.get_ubkg_valueset(current_app.ubkg.entities)
    return build_enum_class('Entities', {'SOURCE': 'source', 'SAMPLE': 'sample', 'DATASET': 'dataset'})

def specimen_categories():
    response = current_app.ubkg.get_ubkg_valueset(current_app.ubkg.specimen_categories)
    return build_enum_class('SpecimenCategories', response, 'term')

def specimen_categories_as_arr():
    SpecimenCategories = specimen_categories()
    return list(map(enum_val, SpecimenCategories))

def organ_types():
    response = current_app.ubkg.get_ubkg_valueset(current_app.ubkg.organ_types)
    return build_enum_class('OrganTypes', response, 'term')

def init_ontology():
    specimen_categories()
    organ_types()
    entities()

class Ontology:
    @staticmethod
    def entities():
        return entities()

