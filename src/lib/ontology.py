from atlas_consortia_commons.object import build_enum_class
from flask import current_app

def entities():
    #TODO use when resolved in api
    response = current_app.ubkg.get_ubkg_valueset(current_app.ubkg.entities)
    return build_enum_class('Entities', {'SOURCE': 'Source', 'SAMPLE': 'Sample', 'DATASET': 'Dataset'})

def specimen_categories():
    response = current_app.ubkg.get_ubkg_valueset(current_app.ubkg.specimen_categories)
    return build_enum_class('SpecimenCategories', response, 'term')

def specimen_categories_as_arr():
    SpecimenCategories = specimen_categories()
    return list(map(str, SpecimenCategories))

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

