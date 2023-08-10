from atlas_consortia_commons.ubkg.ubkg_sdk import UbkgSDK
from flask import current_app


def get_organ_types_ep():
    return UbkgSDK.get_endpoint(current_app.ubkg.organ_types)


def get_assay_types_ep():
    return UbkgSDK.get_endpoint(current_app.ubkg.assay_types)


class Ontology(UbkgSDK):
    @staticmethod
    def assay_types_ext():
        Ontology.Ops.key = 'data_type'
        Ontology.Ops.url_params = '&dataset_provider=external'
        return Ontology.transform_ontology(current_app.ubkg.assay_types, 'AssayTypesExt')