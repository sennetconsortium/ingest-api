import logging

from flask import Blueprint, request, make_response, jsonify
from hubmap_commons.hm_auth import AuthHelper

privs_blueprint = Blueprint('privs', __name__)
logger = logging.getLogger(__name__)



@privs_blueprint.route('/privs')
def privs_for_groups_token():
    groups_token: str = get_groups_token()
    auth_helper_instance: AuthHelper = AuthHelper.instance()
    read_privs: bool = auth_helper_instance.has_read_privs(groups_token)
    write_privs: bool = auth_helper_instance.has_write_privs(groups_token)
    data: dict = {
        "read_privs": read_privs,
        "write_privs": write_privs
    }
    headers: dict = {
        "Content-Type": "application/json"
    }
    return make_response(jsonify(data), 200, headers)


#  403: not authorized; 401: invalid token; 400: invalid group uuid provided
@privs_blueprint.route('/privs/<group_uuid>/has-write')
def privs_has_write_on_group_uuid(group_uuid):
    groups_token: str = get_groups_token()
    auth_helper_instance: AuthHelper = AuthHelper.instance()
    has_write_privs: bool = auth_helper_instance.check_write_privs(groups_token, group_uuid)
    headers: dict = {
        "Content-Type": "application/json"
    }
    return make_response(jsonify({"has_write_privs": has_write_privs}), 200, headers)


def get_groups_token() -> str:
    return request.headers.get('authorization')[7:]
