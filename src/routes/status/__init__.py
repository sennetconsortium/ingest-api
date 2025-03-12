from flask import Blueprint, current_app, jsonify, request
from pathlib import Path
import logging

from hubmap_commons import string_helper, net_helper
from lib.neo4j_helper import Neo4jHelper
from jobs import JobQueue

status_blueprint = Blueprint('status', __name__)
logger = logging.getLogger(__name__)

"""
Show status of the current VERSION and BUILD
Returns
-------
json
    A json containing the status details
"""


@status_blueprint.route('/status', methods=['GET'])
def get_status():
    try:
        response_code = 200

        response_data = {
            # Use strip() to remove leading and trailing spaces, newlines, and tabs
            'version': (Path(__file__).absolute().parent.parent.parent.parent / 'VERSION').read_text().strip(),
            'build': (Path(__file__).absolute().parent.parent.parent.parent / 'BUILD').read_text().strip()
        }

        if current_app.config.get("REDIS_MODE"):
            redis_connected = JobQueue.is_connected(current_app.config['REDIS_SERVER'])
            response_data['redis_connection'] = redis_connected
            if not redis_connected:
                response_code = 500

        # if ?check-ws-dependencies=true is present in the url request params
        # set a flag to check these other web services
        check_ws_calls = string_helper.isYes(request.args.get('check-ws-dependencies'))

        # check the neo4j connection
        try:
            with Neo4jHelper.get_instance().session() as session:
                res = session.run("MATCH () RETURN TRUE AS connected LIMIT 1").single()
                is_connected = res['connected']

        # the neo4j connection will often fail via exception so
        # catch it here, flag as failure and track the returned error message
        except Exception as e:
            response_code = 500
            response_data['neo4j_error'] = str(e)
            is_connected = False

        if is_connected:
            response_data['neo4j_connection'] = True
        else:
            response_code = 500
            response_data['neo4j_connection'] = False

        # if the flag was set to check ws dependencies do it now
        # for each dependency try to connect via helper which calls the
        # service's /status method
        # The helper method will return False if the connection fails or
        # an integer with the number of milliseconds that it took to get
        # the services status
        if check_ws_calls:
            uuid_ws_url = current_app.config['UUID_WEBSERVICE_URL'].strip()
            uuid_ws_check = net_helper.check_hm_ws(uuid_ws_url)
            entity_ws_check = net_helper.check_hm_ws(current_app.config['ENTITY_WEBSERVICE_URL'])
            search_ws_check = net_helper.check_hm_ws(current_app.config['SEARCH_WEBSERVICE_URL'])
            if not uuid_ws_check or not entity_ws_check or not search_ws_check:
                response_code = 500
            response_data['uuid_ws'] = uuid_ws_check
            response_data['entity_ws'] = entity_ws_check
            response_data['search_ws_check'] = search_ws_check

    # catch any unhandled exceptions
    except Exception as e:
        response_code = 500
        response_data['exception_message'] = str(e)
    finally:
        return jsonify(response_data), response_code
