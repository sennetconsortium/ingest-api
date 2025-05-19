import logging
from typing import List

from flask import Blueprint, Response, jsonify, make_response, request
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.hm_auth import AuthHelper

privs_blueprint = Blueprint("privs", __name__)
logger = logging.getLogger(__name__)


@privs_blueprint.route("/privs")
def privs_for_groups_token():
    groups_token: str = get_groups_token()
    auth_helper_instance: AuthHelper = AuthHelper.instance()

    read_privs = auth_helper_instance.has_read_privs(groups_token)
    if isinstance(read_privs, Response):
        return read_privs

    write_privs = auth_helper_instance.has_write_privs(groups_token)
    if isinstance(write_privs, Response):
        return write_privs

    data: dict = {"read_privs": read_privs, "write_privs": write_privs}
    headers: dict = {"Content-Type": "application/json"}
    return make_response(jsonify(data), 200, headers)


#  403: not authorized; 401: invalid token; 400: invalid group uuid provided
@privs_blueprint.route("/privs/<group_uuid>/has-write")
def privs_has_write_on_group_uuid(group_uuid):
    groups_token: str = get_groups_token()
    auth_helper_instance: AuthHelper = AuthHelper.instance()
    try:
        has_write_privs: bool = auth_helper_instance.check_write_privs(groups_token, group_uuid)
        if isinstance(has_write_privs, Response):
            return has_write_privs
    except HTTPException as e:
        return make_response(e.description, e.status_code)
    headers: dict = {"Content-Type": "application/json"}
    data: dict = {"group_uuid": group_uuid, "has_write_privs": has_write_privs}
    return make_response(jsonify(data), 200, headers)


# a list of groups that the user is a member of with write privs
@privs_blueprint.route("/privs/user-write-groups")
def privs_get_user_write_groups():
    groups_token: str = get_groups_token()
    auth_helper_instance: AuthHelper = AuthHelper.instance()

    user_write_groups: List[dict] = auth_helper_instance.get_user_write_groups(groups_token)
    if isinstance(user_write_groups, Response):
        return user_write_groups

    headers: dict = {"Content-Type": "application/json"}
    return make_response(jsonify({"user_write_groups": user_write_groups}), 200, headers)


@privs_blueprint.route("/privs/has-data-admin")
def privs_has_data_admin_privs():
    groups_token: str = get_groups_token()
    auth_helper_instance: AuthHelper = AuthHelper.instance()

    data_admin_privs: List[dict] = auth_helper_instance.has_data_admin_privs(groups_token)
    if isinstance(data_admin_privs, Response):
        return data_admin_privs

    headers: dict = {"Content-Type": "application/json"}
    return make_response(jsonify({"has_data_admin_privs": data_admin_privs}), 200, headers)


def get_groups_token() -> str:
    return (
        request.headers.get("authorization")[7:]
        if request.headers.get("authorization") is not None
        else ""
    )
