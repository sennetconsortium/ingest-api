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
        def key_callback(dict):
            return dict['name']
        
        def val_callback(dict):
       
            list_of_facets = []
            for modality in dict:
                list_of_facets.append(modality['name'])
            return list_of_facets
        
        return cls.ops(
            as_data_dict=True, key_callback=key_callback, val_callback=val_callback, data_as_val=False
        ).dataset_types_hierarchy()
