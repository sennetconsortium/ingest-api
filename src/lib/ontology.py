import logging

from atlas_consortia_commons.object import build_enum_class
from atlas_consortia_commons.ubkg import get_from_node
from atlas_consortia_commons.string import to_snake_case_upper, equals

from flask import current_app

logger = logging.getLogger(__name__)


def _get_obj_type(in_enum, as_data_dict: bool = False):
    if as_data_dict:
        return 'dict'
    else:
        return 'enum' if in_enum else 'class'


def _get_response(obj):
    if type(obj) is not str and get_from_node(obj, 'endpoint'):
        return current_app.ubkg.get_ubkg_by_endpoint(obj)
    else:
        return current_app.ubkg.get_ubkg_valueset(obj)


def _build_enum_class(name: str, obj, key: str = 'term', val_key: str = None, prop_callback=to_snake_case_upper,
                      obj_type: str = 'class', data_as_val=False):
    response = _get_response(obj)
    return build_enum_class(name, response, key, val_key=val_key, prop_callback=prop_callback,
                            obj_type=obj_type, data_as_val=data_as_val)


def entities(in_enum: bool = False, as_data_dict: bool = False):
    return _build_enum_class('Entities', current_app.ubkg.entities, obj_type=_get_obj_type(in_enum, as_data_dict))


def specimen_categories(in_enum: bool = False, as_data_dict: bool = False):
    return _build_enum_class('SpecimenCategories', current_app.ubkg.specimen_categories,
                             obj_type=_get_obj_type(in_enum, as_data_dict))


def organ_types(in_enum: bool = False, as_data_dict: bool = False):
    return _build_enum_class('OrganTypes', current_app.ubkg.organ_types, key='rui_code', val_key='term',
                             obj_type=_get_obj_type(in_enum, as_data_dict))


def assay_types(in_enum: bool = False, as_data_dict: bool = False,
                prop_callback=to_snake_case_upper, data_as_val=False):
    return _build_enum_class('AssayTypes', current_app.ubkg.assay_types, key='data_type',
                             obj_type=_get_obj_type(in_enum, as_data_dict),
                             prop_callback=prop_callback, data_as_val=data_as_val)


def source_types(in_enum: bool = False, as_data_dict: bool = False):
    return _build_enum_class('SourceTypes', current_app.ubkg.source_types,
                             obj_type=_get_obj_type(in_enum, as_data_dict))


def init_ontology():
    specimen_categories()
    organ_types()
    entities()
    assay_types()
    source_types()

def enum_val_lower(val):
    return val.value.lower()

def ubkg_sever():
    return current_app.config['UBKG_SERVER']

def get_valueset_ep(code):
    ep = f"{ubkg_sever()}{current_app.config['UBKG_ENDPOINT_VALUESET']}"
    return ep.format(code=code)

def get_organ_types_ep():
    return f"{ubkg_sever()}{get_from_node(current_app.ubkg.organ_types, 'endpoint')}"

def get_assay_types_ep():
    return f"{ubkg_sever()}{get_from_node(current_app.ubkg.assay_types, 'endpoint')}"


class Ontology:
    @staticmethod
    def entities(as_arr: bool = False, cb=str, as_data_dict: bool = False):
        return Ontology._as_list_or_class(entities(as_arr, as_data_dict), as_arr, cb)

    @staticmethod
    def assay_types(as_arr: bool = False, cb=str, as_data_dict: bool = False, prop_callback=to_snake_case_upper, data_as_val=False):
        return Ontology._as_list_or_class(assay_types(as_arr, as_data_dict, prop_callback,
                                                      data_as_val=data_as_val), as_arr, cb)

    @staticmethod
    def specimen_categories(as_arr: bool = False, cb=str, as_data_dict: bool = False):
        return Ontology._as_list_or_class(specimen_categories(as_arr, as_data_dict), as_arr, cb)

    @staticmethod
    def organ_types(as_arr: bool = False, cb=str, as_data_dict: bool = False):
        return Ontology._as_list_or_class(organ_types(as_arr, as_data_dict), as_arr, cb)

    @staticmethod
    def source_types(as_arr: bool = False, cb=str, as_data_dict: bool = False):
        return Ontology._as_list_or_class(source_types(as_arr, as_data_dict), as_arr, cb)

    @staticmethod
    def _as_list_or_class(obj, as_arr: bool = False, cb=str):
        return obj if not as_arr else list(map(cb, obj))