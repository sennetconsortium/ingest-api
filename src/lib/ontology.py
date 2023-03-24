from atlas_consortia_commons.object import build_enum_class
from flask import current_app

def entities():
    response = current_app.ubkg.get_ubkg_valueset(current_app.ubkg.entities)
    return build_enum_class('Entities', response, 'term')

def specimen_categories():
    response = current_app.ubkg.get_ubkg_valueset(current_app.ubkg.specimen_categories)
    return build_enum_class('SpecimenCategories', response, 'term')

def organ_types():
    response = current_app.ubkg.get_ubkg_valueset(current_app.ubkg.organ_types)
    return build_enum_class('OrganTypes', response, 'term')

def init_ontology():
    specimen_categories()
    organ_types()
    entities()

class Ontology:
    @staticmethod
    def entities(as_arr: bool = False):
        Entities = entities()
        return Entities if not as_arr else list(map(str, Entities))

    @staticmethod
    def specimen_categories(as_arr: bool = False):
        SpecimenCategories = specimen_categories()
        return SpecimenCategories if not as_arr else list(map(str, SpecimenCategories))

    @staticmethod
    def organ_types(as_arr: bool = False):
        OrganTypes = organ_types()
        return OrganTypes if not as_arr else list(map(str, OrganTypes))

