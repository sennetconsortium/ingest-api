from atlas_consortia_commons.ubkg.ubkg_sdk import UbkgSDK
from flask import current_app


def get_organ_types_ep():
    return UbkgSDK.get_endpoint(current_app.ubkg.organ_types)


def get_dataset_types_ep():
    return UbkgSDK.get_endpoint(current_app.ubkg.dataset_types)


class Ontology(UbkgSDK):
    pass
