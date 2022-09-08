from flask import Blueprint, jsonify
from pathlib import Path
import logging

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
    return jsonify(status_data)
