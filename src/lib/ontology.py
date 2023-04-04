from atlas_consortia_commons.object import build_enum_class
from atlas_consortia_commons.ubkg import get_from_node
from flask import current_app

def _get_obj_type(in_enum):
    return 'enum' if in_enum else 'class'

def _build_enum_class(name: str, obj, key: str = 'term', in_enum: bool = False):
    response = current_app.ubkg.get_ubkg_valueset(obj)
    return build_enum_class(name, response, key, obj_type=_get_obj_type(in_enum))

def entities(in_enum: bool = False):
    return _build_enum_class('Entities', current_app.ubkg.entities, in_enum=in_enum)

def specimen_categories(in_enum: bool = False):
    return _build_enum_class('SpecimenCategories', current_app.ubkg.specimen_categories, in_enum=in_enum)

def organ_types(in_enum: bool = False):
    return _build_enum_class('OrganTypes', current_app.ubkg.organ_types, in_enum=in_enum)

def source_types(in_enum: bool = False):
    return _build_enum_class('SourceTypes', current_app.ubkg.source_types, in_enum=in_enum)

def data_types(in_enum: bool = False):
    return _build_enum_class('DataTypes', current_app.ubkg.data_types, in_enum=in_enum)

def init_ontology():
    specimen_categories()
    organ_types()
    entities()
    source_types()
    data_types()

def enum_val_lower(val):
    return val.value.lower()

def get_valueset_ep(code):
    ep = f"{current_app.config['UBKG_SERVER']}{current_app.config['UBKG_ENDPOINT_VALUESET']}"
    return ep.format(code=code)

def get_organ_types_ep():
    return get_valueset_ep(get_from_node(current_app.ubkg.organ_types, 'code'))

class Ontology:
    @staticmethod
    def entities(as_arr: bool = False, cb=str):
        return Ontology._as_list_or_class(entities(as_arr), as_arr, cb)

    @staticmethod
    def specimen_categories(as_arr: bool = False, cb=str):
        return Ontology._as_list_or_class(specimen_categories(as_arr), as_arr, cb)

    @staticmethod
    def organ_types(as_arr: bool = False, cb=str):
        return Ontology._as_list_or_class(organ_types(as_arr), as_arr, cb)

    @staticmethod
    def source_types(as_arr: bool = False, cb=str):
        return Ontology._as_list_or_class(source_types(as_arr), as_arr, cb)

    @staticmethod
    def data_types(as_arr: bool = False, cb=str):
        return Ontology._as_list_or_class(data_types(as_arr), as_arr, cb)

    @staticmethod
    def _as_list_or_class(obj, as_arr: bool = False, cb=str):
        return obj if not as_arr else list(map(cb, obj))

