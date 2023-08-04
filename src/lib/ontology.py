import logging

from atlas_consortia_commons.object import build_enum_class
from atlas_consortia_commons.ubkg import get_from_node
from atlas_consortia_commons.string import to_snake_case_upper, equals
import base64

from flask import current_app

logger = logging.getLogger(__name__)

def _get_obj_type(in_enum, as_data_dict: bool = False):
    if as_data_dict:
        return 'dict'
    else:
        return 'enum' if in_enum else 'class'


def _get_response(obj, url_params=None):
    endpoint = get_from_node(obj, 'endpoint')
    if type(obj) is not str and endpoint:
        if url_params is None:
            return current_app.ubkg.get_ubkg_by_endpoint(obj)
        else:
            key = base64.b64encode(url_params.encode('utf-8')).decode('utf-8')
            key = key.replace("=", '')
            return current_app.ubkg.get_ubkg(obj, key, f"{endpoint}{url_params}")
    else:
        return current_app.ubkg.get_ubkg_valueset(obj)

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
    class Ops:
        as_arr = False
        cb = str
        as_data_dict = False
        prop_callback = to_snake_case_upper
        data_as_val = False
        url_params = None
        key = 'term'
        obj_type = 'class'
        val_key = None

    @staticmethod
    def ops(as_arr: bool = False, cb=str, as_data_dict: bool = False, prop_callback=to_snake_case_upper,
            data_as_val=False, url_params=None, key='term', val_key=None):
        Ontology.Ops.as_arr = as_arr
        Ontology.Ops.cb = cb
        Ontology.Ops.as_data_dict = as_data_dict
        Ontology.Ops.prop_callback = prop_callback
        Ontology.Ops.data_as_val = data_as_val
        Ontology.Ops.url_params = url_params
        Ontology.Ops.key = key
        Ontology.Ops.val_key = val_key
        return Ontology

    @staticmethod
    def transform_ontology(obj, class_name):
        response = _get_response(obj, url_params=Ontology.Ops.url_params)
        obj = build_enum_class(class_name, response,
                               prop_key=Ontology.Ops.key, val_key=Ontology.Ops.val_key,
                               prop_callback=Ontology.Ops.prop_callback,
                               obj_type=_get_obj_type(Ontology.Ops.as_arr, Ontology.Ops.as_data_dict),
                               data_as_val=Ontology.Ops.data_as_val)
        return Ontology._as_list_or_class(obj, Ontology.Ops.as_arr, Ontology.Ops.cb)

    @staticmethod
    def entities():
        return Ontology.transform_ontology(current_app.ubkg.entities, 'Entities')

    @staticmethod
    def assay_types():
        Ontology.Ops.key = 'data_type'
        return Ontology.transform_ontology(current_app.ubkg.assay_types, 'AssayTypes')

    @staticmethod
    def assay_types_ext():
        Ontology.Ops.key = 'data_type'
        Ontology.Ops.url_params = '&dataset_provider=external'
        return Ontology.transform_ontology(current_app.ubkg.assay_types, 'AssayTypesExt')

    @staticmethod
    def specimen_categories():
        return Ontology.transform_ontology(current_app.ubkg.specimen_categories, 'SpecimenCategories')

    @staticmethod
    def organ_types():
        Ontology.Ops.key = 'rui_code'
        Ontology.Ops.val_key = 'term'
        return Ontology.transform_ontology(current_app.ubkg.organ_types, 'OrganTypes')

    @staticmethod
    def source_types():
        return Ontology.transform_ontology(current_app.ubkg.source_types, 'SourceTypes')

    @staticmethod
    def _as_list_or_class(obj, as_arr: bool = False, cb=str):
        return obj if not as_arr else list(map(cb, obj))


def init_ontology():
    Ontology.specimen_categories()
    Ontology.organ_types()
    Ontology.entities()
    Ontology.assay_types()
    Ontology.source_types()

