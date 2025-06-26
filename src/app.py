import argparse
import datetime
import json
import logging
import os

import requests
from atlas_consortia_commons.converter import EntityUUIDConverter
from atlas_consortia_commons.rest import abort_err_handler, get_http_exceptions_classes
from atlas_consortia_commons.ubkg import initialize_ubkg
from atlas_consortia_commons.ubkg.ubkg_sdk import init_ontology
from flask import Flask
from hubmap_commons import neo4j_driver

# HuBMAP commons
from hubmap_commons.hm_auth import AuthHelper
from redis import from_url

# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import submodules
from jobs import JobQueue
from jobs.cache.datasets import (
    schedule_update_dataset_sankey_data,
    schedule_update_datasets_datastatus,
)
from jobs.cache.uploads import schedule_update_uploads_datastatus

# Local Modules
from lib.file_upload_helper import UploadFileHelper
from lib.neo4j_helper import Neo4jHelper
from lib.vitessce import VitessceConfigCache
from routes.admin import admin_blueprint
from routes.assayclassifier import assayclassifier_blueprint
from routes.auth import auth_blueprint
from routes.collections import collections_blueprint
from routes.entity_CRUD import entity_CRUD_blueprint
from routes.file import file_blueprint
from routes.jobs import jobs_blueprint
from routes.metadata import metadata_blueprint
from routes.privs import privs_blueprint
from routes.samples import samples_blueprint
from routes.sankey_data import sankey_data_blueprint
from routes.sources import sources_blueprint
from routes.status import status_blueprint
from routes.vitessce import vitessce_blueprint

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(
    __name__,
    instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), "instance"),
    instance_relative_config=True,
)
app.config.from_pyfile("app.cfg")
app.app_context().push()
app.url_map.converters["entity_uuid"] = EntityUUIDConverter

app.vitessce_cache = None

if app.config.get("REDIS_MODE", False):
    JobQueue.create(app.config["REDIS_SERVER"], "default")

app.register_blueprint(auth_blueprint)
app.register_blueprint(status_blueprint)
app.register_blueprint(privs_blueprint)
app.register_blueprint(entity_CRUD_blueprint)
app.register_blueprint(metadata_blueprint)
app.register_blueprint(file_blueprint)
app.register_blueprint(assayclassifier_blueprint)
app.register_blueprint(vitessce_blueprint)
app.register_blueprint(jobs_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(sources_blueprint)
app.register_blueprint(samples_blueprint)
app.register_blueprint(collections_blueprint)
app.register_blueprint(sankey_data_blueprint)

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

####################################################################################################
## UBKG Ontology and REST initialization
####################################################################################################

try:
    for exception in get_http_exceptions_classes():
        app.register_error_handler(exception, abort_err_handler)
    app.ubkg = initialize_ubkg(app.config)
    with app.app_context():
        init_ontology()

    logger.info("Initialized ubkg module successfully :)")

# Use a broad catch-all here
except Exception:
    msg = "Failed to initialize the ubkg module"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)


####################################################################################################
## Dataset Hierarchy initialization
####################################################################################################

try:
    with open(app.config["HIERARCHY_JSON_FILE"], "r") as file:
        app.config["DATASET_TYPE_HIERARCHY"] = json.load(file)
except FileNotFoundError:
    print(f"Error: The file dataset_type_hierarchy.json was not found.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")


####################################################################################################
## AuthHelper initialization
####################################################################################################

# Initialize AuthHelper class and ensure singleton
try:
    if AuthHelper.isInitialized() == False:
        auth_helper_instance = AuthHelper.create(
            app.config["APP_CLIENT_ID"], app.config["APP_CLIENT_SECRET"]
        )

        logger.info("Initialized AuthHelper class successfully :)")
    else:
        auth_helper_instance = AuthHelper.instance()
except Exception:
    msg = "Failed to initialize the AuthHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)

####################################################################################################
## Neo4j connection initialization
####################################################################################################

# The neo4j_driver (from commons package) is a singleton module
# This neo4j_driver_instance will be used for application-specific neo4j queries
# as well as being passed to the schema_manager
try:
    neo4j_driver_instance = neo4j_driver.instance(
        app.config["NEO4J_SERVER"], app.config["NEO4J_USERNAME"], app.config["NEO4J_PASSWORD"]
    )

    Neo4jHelper.set_instance(neo4j_driver_instance)

    logger.info("Initialized neo4j_driver module successfully :)")
except Exception:
    msg = "Failed to initialize the neo4j_driver module"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)

####################################################################################################
## File upload initialization
####################################################################################################

try:
    # Initialize the UploadFileHelper class and ensure singleton
    if UploadFileHelper.is_initialized() == False:
        file_upload_helper_instance = UploadFileHelper.create(
            app.config["FILE_UPLOAD_TEMP_DIR"],
            app.config["FILE_UPLOAD_DIR"],
            app.config["UUID_WEBSERVICE_URL"],
        )

        logger.info("Initialized UploadFileHelper class successfully :)")

        # This will delete all the temp dirs on restart
        # file_upload_helper_instance.clean_temp_dir()
    else:
        file_upload_helper_instance = UploadFileHelper.instance()
# Use a broad catch-all here
except Exception:
    msg = "Failed to initialize the UploadFileHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)

####################################################################################################
## Redis client initialization
####################################################################################################

redis_client_instance = None

if app.config.get("REDIS_MODE", True):
    try:
        redis_client_instance = from_url(app.config["REDIS_SERVER"])

        app.vitessce_cache = VitessceConfigCache(redis_client_instance)

        logger.info(
            f'Connected to Redis server {redis_client_instance.execute_command("INFO")["redis_version"]} successfully :)'
        )
    except Exception:
        msg = "Failed to connect to the Redis cluster"
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)


# The only endpoint that should be in this file, all others should be route Blueprints...
@app.route("/", methods=["GET"])
def index():
    return "Hello! This is SenNet Ingest API service :)"


if app.config.get("REDIS_MODE"):
    logger.info("Scheduling cache jobs in RQ worker")
    # schedule the cache jobs
    job_queue = JobQueue.instance()
    schedule_update_datasets_datastatus(job_queue, delta=datetime.timedelta(seconds=30))
    schedule_update_uploads_datastatus(job_queue, delta=datetime.timedelta(seconds=30))
    schedule_update_dataset_sankey_data(
        job_queue=job_queue, delta=datetime.timedelta(seconds=30), authorized=False
    )
    schedule_update_dataset_sankey_data(
        job_queue=job_queue, delta=datetime.timedelta(seconds=30), authorized=True
    )

# For local development/testing
if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port")
        args = parser.parse_args()
        port = 8484
        if args.port:
            port = int(args.port)
        app.run(port=port, host="0.0.0.0")
    finally:
        pass
