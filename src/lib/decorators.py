import contextlib
import os
from functools import wraps
from inspect import signature

from atlas_consortia_commons.rest import abort_bad_req, abort_forbidden
from flask import current_app, request
from hubmap_commons.hm_auth import AuthHelper


def require_json(param: str = "body"):
    """A decorator that checks if the request content type is json.

    If the decorated function has a parameter with the same name as `param`, the
    request body will be passed as that parameter.

    Parameters
    ----------
    param : str
        The name of the parameter to pass the request body to required.
        Defaults to "body".

    Notes
    -----
    This decorator does not do any validation on the json request body.

    Example
    -------
        @app.route("/foo", methods=["POST"])
        @require_json(param="foo_body")
        def foo(foo_body: dict):
            return jsonify(foo_body)

        @app.route("/bar", methods=["PUT"])
        @require_json()
        def bar(body: dict):
            return jsonify(body)
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                abort_bad_req(
                    "A json body and appropriate Content-Type header are required"
                )

            if param and param in signature(f).parameters:
                kwargs[param] = request.json

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_data_admin(param: str = "token"):
    """A decorator that checks if the user is a member of the SenNet Data Admin group.

    If the decorated function has a parameter with the same name as `param`, the
    user's token will be passed as that parameter. If the request has no token or
    an invalid Data Admin token, a 403 Forbidden response will be returned.

    Parameters
    ----------
    param : str
        The name of the parameter to pass the user's token to. Defaults to "token".

    Example
    -------
        @app.route("/foo", methods=["POST"])
        @require_data_admin(param="foo_token")
        def foo(foo_token: str):
            return jsonify({"message": f"You are a data admin with token {foo_token}!"})

        @app.route("/bar", methods=["PUT"])
        @require_data_admin()
        def bar(token: str):
            return jsonify({"message": f"You are a data admin with token {token}!"})
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_helper = AuthHelper.configured_instance(
                current_app.config["APP_CLIENT_ID"],
                current_app.config["APP_CLIENT_SECRET"],
            )
            token = auth_helper.getUserTokenFromRequest(request, getGroups=True)
            if not isinstance(token, str):
                abort_forbidden("User must be a member of the SenNet Data Admin group")

            is_data_admin = auth_helper.has_data_admin_privs(token)
            if is_data_admin is not True:
                abort_forbidden("User must be a member of the SenNet Data Admin group")

            if param and param in signature(f).parameters:
                kwargs[param] = token

            return f(*args, **kwargs)

        return decorated_function

    return decorator

            if param in signature(f).parameters:
                kwargs[param] = token

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
