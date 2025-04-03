import json
import logging
import time
from typing import Callable, List, Optional, Union

import requests
from atlas_consortia_commons.file import ensure_trailing_slash_url
from flask import current_app, request
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.file_helper import removeTrailingSlashURL, ensureTrailingSlashURL
from hubmap_commons.hm_auth import AuthHelper
from hubmap_sdk import Entity, EntitySdk, SearchSdk
from hubmap_sdk.sdk_helper import make_entity
from requests.adapters import HTTPAdapter, Retry

from lib.entities.source import Source
from routes.auth import get_auth_header_dict

logger = logging.getLogger(__name__)


def get_token() -> Optional[str]:
    auth_helper_instance = AuthHelper.instance()
    token = auth_helper_instance.getAuthorizationTokens(request.headers)
    if not isinstance(token, str):
        token = None
    return token


def get_entity_by_id(identifier, token=None):
    service_url = ensure_trailing_slash_url(current_app.config["ENTITY_WEBSERVICE_URL"])
    url = f"{service_url}entities/{identifier}"
    if token is None:
        response = requests.get(url)
    else:
        response = requests.get(url, headers=get_auth_header_dict(token))

    if not response.ok:
        msg = response.json().get("error", "Unknown error")
        raise HTTPException(msg, response.status_code)

    output = response.json()
    entity = {}
    if output is not None and 'entity_type' in output:
        if output['entity_type'].lower() == 'source':
            entity = Source(output)
        else:
            entity = make_entity(output)
    return entity


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
    hubmap_commons.exceptions.HTTPException
        If the entity-api request fails.
    """
    entity = get_entity_by_id(entity_id, token)
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
        The groups token for the request if available.
    as_dict : bool, optional
        Should entity be returned as a dictionary, by default False.

    Returns
    -------
    Union[hubmap_sdk.Entity, dict]
        The entity from search-api for the given uuid.

    Raises
    ------
    hubmap_commons.exceptions.HTTPException
        If the search-api request fails or entity not found.
    """
    search_api_url = current_app.config["SEARCH_WEBSERVICE_URL"]
    search_api = SearchSdk(token=token, service_url=search_api_url)
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
        raise HTTPException("No entity found", 404)

    entity = hits[0]["_source"]
    if as_dict:
        return entity
    return Entity(entity)


def get_associated_sources_from_dataset(
        dataset_id: str, token: str = None, as_dict: bool = False
) -> Union[List[Entity], dict]:
    """Get the associated sources for the given dataset.

    Parameters
    ----------
    dataset_id : str
        The uuid of the dataset.
    token : str
        The groups token for the request.
    as_dict : bool, optional
        Should entity be returned as a dictionary, by default False.

    Returns
    -------
    Union[List[Entity], dict]
        The associated sources for the given dataset.

    Raises
    ------
    hubmap_commons.exceptions.HTTPException
        If the entiti-api request fails or entity not found.
    """
    entity_api_url = ensureTrailingSlashURL(current_app.config["ENTITY_WEBSERVICE_URL"])
    url = f"{entity_api_url}datasets/{dataset_id}/sources"
    headers = {}
    if token is not None:
        headers = {"Authorization": f"Bearer {token}"}
    res = requests.get(url, headers=headers)
    if not res.ok:
        raise HTTPException(f"Failed to get associated source for dataset {dataset_id}")
    body = res.json()

    if as_dict:
        return body

    if isinstance(body, list):
        return [Entity(entity) for entity in res.json()]

    return [Entity(body)]


def reindex_entities(entity_ids: list, token: str) -> None:
    """Reindex the entities in the search-api.

    Parameters
    ----------
    entity_ids : list
        The list of uuids of the entities to be reindexed.
    token : str
        The groups token for the request.

    Raises
    ------
    hubmap_commons.exceptions.HTTPException
        If the search-api request fails or entity not found.
    """
    search_api_url = current_app.config["SEARCH_WEBSERVICE_URL"]
    search_api = SearchSdk(token=token, service_url=search_api_url)
    errors = {}
    for entity_id in entity_ids:
        try:
            search_api.reindex(entity_id)
        except HTTPException as e:
            errors[entity_id] = str(e)

    if len(errors) > 0:
        msg = "; ".join([f"{k}: {v}" for k, v in errors.items()])
        raise HTTPException(msg)


def bulk_update_entities(
        entity_updates: dict,
        token: str,
        total_tries: int = 3,
        throttle: float = 5,
        entity_api_url: Optional[str] = None,
        after_each_callback: Optional[Callable[[int], None]] = None,
) -> dict:
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
    after_each_callback : Callable[[int], None], optional
        A callback function to be called after each update, by default None. The index
        of the update is passed as a parameter to the callback.

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
                    f"{entity_api_url}/entities/{uuid}?return_dict=true",
                    json=payload,
                    timeout=15,
                )
                results[uuid] = {
                    "success": res.ok,
                    "data": res.json() if res.ok else error_msg(res.json()),
                }
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to update entity {uuid}: {e}")
                results[uuid] = {"success": False, "data": str(e)}

            if after_each_callback:
                after_each_callback(idx)

            if idx < len(entity_updates) - 1:
                time.sleep(throttle)

    return results


def bulk_create_entities(
        entity_type: str,
        entities: list,
        token: str,
        total_tries: int = 3,
        throttle: float = 5,
        entity_api_url: Optional[str] = None,
        after_each_callback: Optional[Callable[[int], None]] = None,
) -> list:
    """Bulk create the entities in the entity-api.

    This function supports request throttling and retries.

    Parameters
    ----------
    entity_type : str
        The type of the entity to be created. Cooresponds to the entity-api endpoint.
    entities : list
        The list of dictionaries representing the entities. Each dictionary is the
        create entity payload.
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
    after_each_callback : Callable[[int], None], optional
        A callback function to be called after each create, by default None. The index
        of the create is passed as a parameter to the callback.

    Returns
    -------
    list
        The results of the bulk create. If successful, the value is a list of
        dictionaries with "success" as True and "data" as the entity data. If failed,
        the value is a list of dictionaries with "success" as False and "data" as the
        error message.
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

    results = []
    with session as s:
        for idx, payload in enumerate(entities):
            try:
                res = s.post(
                    f"{entity_api_url}/entities/{entity_type.lower()}",
                    json=payload,
                    timeout=15,
                )
                results.append(
                    {
                        "success": res.ok,
                        "data": res.json() if res.ok else error_msg(res.json()),
                    }
                )
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to create entity: {e}")
                results.append({"success": False, "data": str(e)})

            if after_each_callback:
                after_each_callback(idx)

            if idx < len(entities) - 1:
                time.sleep(throttle)

    return results


def error_msg(json_res: dict) -> str:
    """Get the error message from the json response.

    Parameters
    ----------
    json_res : dict
        The json response from the request.

    Returns
    -------
    str
        The error message from the json response.
    """
    if "error" in json_res:
        return json_res["error"]
    if "message" in json_res:
        return json_res["message"]

    return str(json_res)


def obj_to_dict(obj) -> dict:
    """
    Convert the obj[ect] into a dict, but deeply.
    Note: The Python builtin 'vars()' does not work here because of the way that some of the classes
    are defined.
    """
    return json.loads(
        json.dumps(obj, default=lambda o: getattr(o, '__dict__', str(o)))
    )


def entity_json_dumps(entity: Entity, token: str, entity_sdk: EntitySdk, to_file: False):
    """
    Because entity and the content of the arrays returned from entity_instance.get_associated_*
    contain user defined objects we need to turn them into simple python objects (e.g., dicts, lists, str)
    before we can convert them wth json.dumps.
    Here we create an expanded version of the entity associated with the dataset_uuid and return it as a json string.
    """
    dataset_uuid = entity.get_uuid()
    entity = obj_to_dict(entity)
    entity['organs'] = obj_to_dict(entity_sdk.get_associated_organs_from_dataset(dataset_uuid))
    entity['samples'] = obj_to_dict(entity_sdk.get_associated_samples_from_dataset(dataset_uuid))
    entity['sources'] = get_associated_sources_from_dataset(dataset_uuid, as_dict=True)

    # Return as a string to be fed into a file
    if to_file:
        json_object = json.dumps(entity, indent=4)
        json_object += '\n'
        return json_object
    # Return as a dict for JSON response
    else:
        return entity
