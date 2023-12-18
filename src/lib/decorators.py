from functools import wraps

from atlas_consortia_commons.rest import abort_bad_req
from flask import request


def require_json(f):
    """A decorator that checks if the request content type is json"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            abort_bad_req("A json body and appropriate Content-Type header are required")
        return f(*args, **kwargs)

    return decorated_function
