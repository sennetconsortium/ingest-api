from typing import List, Optional, Union

import requests
from flask import current_app
from hubmap_sdk import Entity, EntitySdk, SearchSdk
from hubmap_sdk.sdk_helper import HTTPException as SDKException


def get_entity(
    entity_id: str, token: Optional[str], as_dict: bool = False
) -> Union[Entity, dict]:
    """Get the entity from entity-api for the given uuid.

    Parameters
    ----------
    entity_id : str
        The uuid of the entity.
    token : Optional[str]
        The groups token for the request if available

    Returns
    -------
    Union[hubmap_sdk.Entity, dict]
        The entity from entity-api for the given uuid.

    Raises
    ------
    hubmap_sdk.sdk_helper.HTTPException
        If the entity-api request fails.
    """
    entity_api_url = current_app.config["ENTITY_WEBSERVICE_URL"]
    entity_api = EntitySdk(token=token, service_url=entity_api_url)
    try:
        entity = entity_api.get_entity_by_id(entity_id)
    except SDKException:
        entity_api = EntitySdk(service_url=entity_api_url)
        entity = entity_api.get_entity_by_id(entity_id)  # may again raise SDKException

    if as_dict:
        return vars(entity)
    return entity


def get_entity_from_search_api(
    entity_id: str, token: Optional[str], as_dict: bool = False
) -> Union[Entity, dict]:
    """Get the entity from search-api for the given uuid.

    Parameters
    ----------
    entity_id : str
        The uuid of the entity.
    token : Optional[str]
        The groups token for the request if available
    as_dict : bool, optional
        Should entity be returned as a dictionary, by default False

    Returns
    -------
    Union[hubmap_sdk.Entity, dict]
        The entity from search-api for the given uuid.

    Raises
    ------
    hubmap_sdk.sdk_helper.HTTPException
        If the search-api request fails or entity not found
    """
    search_api_url = current_app.config["SEARCH_WEBSERVICE_URL"]
    search_api = SearchSdk(token=token, service_url=search_api_url)
    try:
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "should": [
                        {"term": {"uuid.keyword": entity_id}},
                        {"term": {"sennet_id.keyword": entity_id}},
                    ]
                }
            },
        }
        res = search_api.search_by_index(query, "entities")
        hits = res.get("hits", {}).get("hits", [])
        if len(hits) == 0 or not hits[0]["_source"]:
            raise SDKException("No entity found", 404)

        entity = hits[0]["_source"]
        if as_dict:
            return entity
        return Entity(entity)

    except SDKException:
        raise


def get_associated_sources_from_dataset(
    dataset_id: str, token: str, as_dict: bool = False
) -> Union[List[Entity], dict]:
    """Get the associated sources for the given dataset.

    Parameters
    ----------
    dataset_id : str
        The uuid of the dataset.
    token : str
        The groups token for the request.
    as_dict : bool, optional
        Should entity be returned as a dictionary, by default False

    Returns
    -------
    Union[List[Entity], dict]
        The associated sources for the given dataset.

    Raises
    ------
    hubmap_sdk.sdk_helper.HTTPException
        If the entiti-api request fails or entity not found
    """
    entity_api_url = current_app.config["ENTITY_WEBSERVICE_URL"]
    url = f"{entity_api_url}/datasets/{dataset_id}/sources"
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.get(url, headers=headers)
    if not res.ok:
        raise SDKException(f"Failed to get associated source for dataset {dataset_id}")
    body = res.json()

    if as_dict:
        return body

    if isinstance(body, list):
        return [Entity(entity) for entity in res.json()]

    return [Entity(body)]
