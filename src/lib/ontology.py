from atlas_consortia_commons.object import build_enum_class
from flask import current_app

def _get_obj_type(in_enum):
    return 'enum' if in_enum else 'class'

def _build_enum_class(name: str, obj, in_enum: bool = False):
    response = current_app.ubkg.get_ubkg_valueset(obj)
    return build_enum_class(name, response, 'term', obj_type=_get_obj_type(in_enum))

def entities(in_enum: bool = False):
    return _build_enum_class('Entities', current_app.ubkg.entities, in_enum)

def specimen_categories(in_enum: bool = False):
    return _build_enum_class('SpecimenCategories', current_app.ubkg.specimen_categories, in_enum)

def organ_types(in_enum: bool = False):
    return _build_enum_class('OrganTypes', current_app.ubkg.organ_types, in_enum)

def source_types(in_enum: bool = False):
    return _build_enum_class('SourceTypes', current_app.ubkg.source_types, in_enum)

def data_types(in_enum: bool = False):
    return _build_enum_class('DataTypes', current_app.ubkg.data_types, in_enum)

def init_ontology():
    specimen_categories()
    organ_types()
    entities()
    source_types()
    data_types()

def enum_val_lower(val):
    return val.value.lower()


class Ontology:
    @staticmethod
    def entities(as_arr: bool = False, cb=str):
        Entities = entities(as_arr)
        return Entities if not as_arr else list(map(cb, Entities))

    @staticmethod
    def specimen_categories(as_arr: bool = False, cb=str):
        SpecimenCategories = specimen_categories(as_arr)
        return SpecimenCategories if not as_arr else list(map(cb, SpecimenCategories))

    @staticmethod
    def organ_types(as_arr: bool = False, cb=str):
        OrganTypes = organ_types(as_arr)
        return OrganTypes if not as_arr else list(map(cb, OrganTypes))

    @staticmethod
    def source_types(as_arr: bool = False, cb=str):
        SourceTypes = source_types(as_arr)
        return SourceTypes if not as_arr else list(map(cb, SourceTypes))

    @staticmethod
    def data_types(as_arr: bool = False, cb=str):
        DataTypes = data_types(as_arr)
        return DataTypes if not as_arr else list(map(cb, DataTypes))

