import logging
import time
from typing import List, Optional, Union

import requests
from flask import current_app
from hubmap_commons.file_helper import removeTrailingSlashURL
from hubmap_sdk import Entity, EntitySdk, SearchSdk
from hubmap_sdk.sdk_helper import HTTPException as SDKException
from requests.adapters import HTTPAdapter, Retry

logger = logging.getLogger(__name__)


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


def bulk_update_entities(
    entity_updates: dict,
    token: str,
    total_tries: int = 3,
    throttle: float = 5,
    entity_api_url: Optional[str] = None,
) -> None:
    """Bulk update the entities in the entity-api.

    This function supports request throttling and retries.

    Parameters
    ----------
    entity_updates : dict
        The dictionary of entity updates. The key is the uuid and the value is the
        update dictionary.
    token : str
        The groups token for the request.
    total_tries : int, optional
        The number of total requests to be made for each update, by default 3.
    throttle : float, optional
        The time to wait between requests and retries, by default 5.
    entity_api_url : str, optional
        The url of the entity-api, by default None. If None, the url is taken from the
        current_app.config. Parameter is used for separate threads where current_app
        is not available.

    Returns
    -------
    dict
        The results of the bulk update. The key is the uuid of the entity. If
        successful, the value is a dictionary with "success" as True and "data" as the
        entity data. If failed, the value is a dictionary with "success" as False and
        "data" as the error message.
    """
    if entity_api_url is None:
        entity_api_url = current_app.config["ENTITY_WEBSERVICE_URL"]
    entity_api_url = removeTrailingSlashURL(entity_api_url)

    headers = {
        "Authorization": f"Bearer {token}",
        "X-SenNet-Application": "ingest-api",
    }
    # create a session with retries
    session = requests.Session()
    session.headers = headers
    retries = Retry(
        total=total_tries,
        backoff_factor=throttle,
        status_forcelist=[500, 502, 503, 504],
    )
    session.mount(entity_api_url, HTTPAdapter(max_retries=retries))

    results = {}
    with session as s:
        for idx, (uuid, payload) in enumerate(entity_updates.items()):
            try:
                res = s.put(
                    f"{entity_api_url}/entities/{uuid}", json=payload, timeout=15
                )
                results[uuid] = {
                    "success": res.ok,
                    "data": res.json() if res.ok else res.json().get("error"),
                }
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to update entity {uuid}: {e}")
                results[uuid] = {"success": False, "data": str(e)}

            if idx < len(entity_updates) - 1:
                time.sleep(throttle)

    return results
