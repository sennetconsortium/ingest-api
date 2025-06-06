import logging
from pathlib import Path

import psutil
from flask import Blueprint, current_app, jsonify, request
from hubmap_commons import net_helper, string_helper

from jobs import JobQueue
from lib.neo4j_helper import Neo4jHelper

status_blueprint = Blueprint("status", __name__)
logger = logging.getLogger(__name__)

"""
Show status of the current VERSION and BUILD
Returns
-------
json
    A json containing the status details
"""


@status_blueprint.route("/status", methods=["GET"])
def get_status():
    try:
        response_code = 200
        response_data = {
            # Use strip() to remove leading and trailing spaces, newlines, and tabs
            "version": (Path(__file__).absolute().parent.parent.parent.parent / "VERSION")
            .read_text()
            .strip(),
            "build": (Path(__file__).absolute().parent.parent.parent.parent / "BUILD")
            .read_text()
            .strip(),
            "usage": [],
            "services": [],
        }

        # Usage
        try:
            # get memory usage
            memory_percent = psutil.virtual_memory().percent
            response_data["usage"].append(
                {
                    "type": "memory",
                    "percent_used": round(memory_percent, 1),
                    "description": "host memory",
                }
            )

            # get disk usage
            disks = current_app.config.get("STATUS_DISKS", {})
            for name, description in disks.items():
                disk_usage = psutil.disk_usage(name)
                storage_percent = (disk_usage.used / disk_usage.total) * 100
                response_data["usage"].append(
                    {
                        "type": "storage",
                        "percent_used": round(storage_percent, 1),
                        "description": description,
                    }
                )
        except Exception as e:
            response_code = 500
            logger.error(f"Error getting system usage: {str(e)}")

        # check redis connection
        if current_app.config.get("REDIS_MODE"):
            redis_connected = JobQueue.is_connected(current_app.config["REDIS_SERVER"])
            service = {"name": "redis", "status": redis_connected}
            if not redis_connected:
                service["message"] = (
                    f"Cannot connect to Redis server at {current_app.config['REDIS_SERVER']}"
                )
                response_code = 500
            response_data["services"].append(service)

        # check the neo4j connection
        try:
            service = {"name": "neo4j", "status": True}
            with Neo4jHelper.get_instance().session() as session:
                res = session.run("MATCH () RETURN TRUE AS connected LIMIT 1").single()
                neo4j_connected = res["connected"]
                if neo4j_connected is False:
                    raise Exception(
                        f"Cannot connect to Neo4j server at {current_app.config['NEO4J_URI']}"
                    )
        except Exception as e:
            response_code = 500
            service["status"] = False
            service["message"] = str(e).replace("'", "")
        response_data["services"].append(service)

        # if ?check-ws-dependencies=true is present in the url request params
        # set a flag to check these other web services
        check_ws_calls = string_helper.isYes(request.args.get("check-ws-dependencies"))

        # if the flag was set to check ws dependencies do it now
        # for each dependency try to connect via helper which calls the
        # service's /status method
        # The helper method will return False if the connection fails or
        # an integer with the number of milliseconds that it took to get
        # the services status
        if check_ws_calls:
            # check the uuid-api connection
            uuid_ws_url = current_app.config["UUID_WEBSERVICE_URL"].strip()
            uuid_ws_check = net_helper.check_hm_ws(uuid_ws_url)
            service = {"name": "uuid-api", "status": True if uuid_ws_check is not False else False}
            if uuid_ws_check is False:
                service["message"] = f"Cannot connect to uuid-api at {uuid_ws_url}"
                response_code = 500
            response_data["services"].append(service)

            # check the entity-api connection
            entity_ws_url = current_app.config["ENTITY_WEBSERVICE_URL"].strip()
            entity_ws_check = net_helper.check_hm_ws(entity_ws_url)
            service = {
                "name": "entity-api",
                "status": True if entity_ws_check is not False else False,
            }
            if entity_ws_check is False:
                service["message"] = f"Cannot connect to entity-api at {entity_ws_url}"
                response_code = 500
            response_data["services"].append(service)

            # check the search-api connection
            search_ws_url = current_app.config["SEARCH_WEBSERVICE_URL"].strip()
            search_ws_check = net_helper.check_hm_ws(search_ws_url)
            service = {
                "name": "search-api",
                "status": True if search_ws_check is not False else False,
            }
            if search_ws_check is False:
                service["message"] = f"Cannot connect to search-api at {search_ws_url}"
                response_code = 500
            response_data["services"].append(service)

    # catch any unhandled exceptions
    except Exception as e:
        response_code = 500
        response_data["message"] = (
            "An error occurred while checking the status of the services: " + str(e)
        )
    finally:
        return jsonify(response_data), response_code
