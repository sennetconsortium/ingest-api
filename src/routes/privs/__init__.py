from flask import Blueprint, session, make_response, jsonify
from flask_cors import cross_origin
import logging

from hubmap_commons.hm_auth import AuthHelper

privs_blueprint = Blueprint('privs', __name__)
logger = logging.getLogger(__name__)


@cross_origin()
@privs_blueprint.route('/privs/for_groups_token/<groups_token>')
def privs_for_groups_token(groups_token: str):
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
@privs_blueprint.route('/privs/has_write_on_group/<group_uuid>')
def privs_has_write_on_group_uuid(group_uuid):
    groups_token = get_groups_token()
    auth_helper_instance = AuthHelper.instance()
    has_privs = auth_helper_instance.check_write_privs(groups_token, group_uuid)
    return make_response(jsonify({"has_privs": has_privs}), 200)
