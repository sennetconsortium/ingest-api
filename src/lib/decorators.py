import contextlib
import os
from functools import wraps
from inspect import signature

from atlas_consortia_commons.rest import abort_bad_req
from flask import request


def require_json(param="body"):
    """A decorator that checks if the request content type is json. If the decorated function
    has a parameter named `param`, the request body will be passed as that parameter

    Args:
        param (str, optional): The name of the parameter to pass the request body to. Defaults to "body".

    Example:
        @app.route("/foo", methods=["POST"])
        @require_json(param="body")
        def foo(body: dict):
            return jsonify(body)
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                abort_bad_req(
                    "A json body and appropriate Content-Type header are required"
                )

            if param in signature(f).parameters:
                kwargs[param] = request.json

            return f(*args, **kwargs)

        return decorated_function

    return decorator


@contextlib.contextmanager
def suppress_print():
    """Context manager to suppress print statements.

    Good for suppressing the output of external libraries that use print statements for
    logging.
    """
    with open(os.devnull, "w") as f, contextlib.redirect_stdout(f):
        yield
