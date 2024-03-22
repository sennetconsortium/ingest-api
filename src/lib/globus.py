import logging
from typing import Optional

from flask import current_app
from globus_sdk import ConfidentialAppAuthClient

logger = logging.getLogger(__name__)


def get_user_id(email: str) -> Optional[str]:
    """Get the user id from the email using the Globus SDK.

    Parameters
    ----------
    email : str
        The email address of the user.

    Returns
    -------
    Optional[str]
        The user id or None if the user is not found.
    """
    client_id = current_app.config["APP_CLIENT_ID"]
    client_secret = current_app.config["APP_CLIENT_SECRET"]
    ac = ConfidentialAppAuthClient(client_id=client_id, client_secret=client_secret)

    try:
        user_res = ac.get_identities(usernames=email)
        if user_res.http_status != 200:
            return None

        data = user_res.data.get("identities", [])
        if len(data) != 1:
            return None

        return data[0].get("id")
    except Exception as e:
        logger.info(f"Error getting user id: {e}")
        return None
