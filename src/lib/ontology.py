from __future__ import annotations

from atlas_consortia_commons.ubkg.ubkg_sdk import UbkgSDK
from flask import current_app


def get_organ_types_ep():
    return UbkgSDK.get_endpoint(current_app.ubkg.organ_types)


def get_dataset_types_ep():
    return UbkgSDK.get_endpoint(current_app.ubkg.dataset_types)


class Ontology(UbkgSDK):

    @classmethod
    def dataset_type_hierarchy(cls: Ontology) -> dict:
        return cls.ops(
            as_data_dict=True, prop_callback=None, data_as_val=False, key="dataset_type", val_key="sennet_dataset_modalities"
        ).dataset_types()
