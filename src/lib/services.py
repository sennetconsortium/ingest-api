from typing import Optional

from flask import current_app
from hubmap_sdk import Entity, EntitySdk
from hubmap_sdk.sdk_helper import HTTPException as SDKException


def get_entity(entity_id: str, token: Optional[str]) -> Entity:
    """Get the entity from entity-api for the given uuid.

    Parameters
    ----------
    entity_id : str
        The uuid of the entity.
    token : Optional[str]
        The groups token for the request if available

    Returns
    -------
    hubmap_sdk.Entity
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

    return entity
