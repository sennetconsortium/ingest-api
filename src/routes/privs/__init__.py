from flask import Blueprint, session, make_response, jsonify
import logging

from hubmap_commons.hm_auth import AuthHelper

privs_blueprint = Blueprint('privs', __name__)
logger = logging.getLogger(__name__)


@privs_blueprint.route('/privs/has_read')
def privs_has_read():
    groups_token = get_groups_token()
    auth_helper_instance = AuthHelper.instance()
    has_privs = auth_helper_instance.has_read_privs(groups_token)
    return make_response(jsonify({"has_privs": has_privs}), 200)


@privs_blueprint.route('/privs/has_write')
def privs_has_write():
    groups_token = get_groups_token()
    auth_helper_instance = AuthHelper.instance()
    has_privs = auth_helper_instance.has_write_privs(groups_token)
    return make_response(jsonify({"has_privs": has_privs}), 200)


#  403: not authorized; 401: invalid token; 400: invalid group uuid provided
@privs_blueprint.route('/privs/has_write_on_group_uuid/<group_uuid>')
def privs_has_write_on_group_uuid(group_uuid):
    groups_token = get_groups_token()
    auth_helper_instance = AuthHelper.instance()
    has_privs = auth_helper_instance.check_write_privs(groups_token, group_uuid)
    return make_response(jsonify({"has_privs": has_privs}), 200)


def get_groups_token():
    return session['tokens']['groups.api.globus.org']['access_token']
