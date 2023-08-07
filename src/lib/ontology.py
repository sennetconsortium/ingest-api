from atlas_consortia_commons.ubkg import get_from_node
from atlas_consortia_commons.ubkg.ubkg_sdk import UbkgSDK
from flask import current_app

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


class Ontology(UbkgSDK):
    @staticmethod
    def assay_types_ext():
        Ontology.Ops.key = 'data_type'
        Ontology.Ops.url_params = '&dataset_provider=external'
        return Ontology.transform_ontology(current_app.ubkg.assay_types, 'AssayTypesExt')
