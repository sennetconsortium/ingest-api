from flask import Blueprint, jsonify, current_app
from pathlib import Path
import logging
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
    status_data = {
        # Use strip() to remove leading and trailing spaces, newlines, and tabs
        'version': (Path(__file__).absolute().parent.parent.parent.parent / 'VERSION').read_text().strip(),
        'build': (Path(__file__).absolute().parent.parent.parent.parent / 'BUILD').read_text().strip()
    }

    if current_app.config.get("REDIS_MODE"):
        status_data['redis_connection'] = JobQueue.is_connected(current_app.config['REDIS_SERVER'])

    return jsonify(status_data)
