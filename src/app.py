import os
import logging
import requests
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
from flask import Flask, g

# HuBMAP commons
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons import neo4j_driver
from atlas_consortia_commons.ubkg import initialize_ubkg
from atlas_consortia_commons.rest import get_http_exceptions_classes, abort_err_handler

from routes.auth import auth_blueprint
from routes.status import status_blueprint
from routes.privs import privs_blueprint
from routes.entity_CRUD import entity_CRUD_blueprint
from routes.validation import validation_blueprint
from routes.file import file_blueprint

# Local Modules
from lib.file_upload_helper import UploadFileHelper
from lib.ontology import init_ontology

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config=True)
app.config.from_pyfile('app.cfg')

app.register_blueprint(auth_blueprint)
app.register_blueprint(status_blueprint)
app.register_blueprint(privs_blueprint)
app.register_blueprint(entity_CRUD_blueprint)
app.register_blueprint(validation_blueprint)
app.register_blueprint(file_blueprint)

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
## AuthHelper initialization
####################################################################################################

# Initialize AuthHelper class and ensure singleton
try:
    if AuthHelper.isInitialized() == False:
        auth_helper_instance = AuthHelper.create(app.config['APP_CLIENT_ID'],
                                                 app.config['APP_CLIENT_SECRET'])

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
    neo4j_driver_instance = neo4j_driver.instance(app.config['NEO4J_SERVER'],
                                                  app.config['NEO4J_USERNAME'],
                                                  app.config['NEO4J_PASSWORD'])

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
        file_upload_helper_instance = UploadFileHelper.create(app.config['FILE_UPLOAD_TEMP_DIR'],
                                                              app.config['FILE_UPLOAD_DIR'],
                                                              app.config['UUID_WEBSERVICE_URL'])

        logger.info("Initialized UploadFileHelper class successfully :)")

        # This will delete all the temp dirs on restart
        #file_upload_helper_instance.clean_temp_dir()
    else:
        file_upload_helper_instance = UploadFileHelper.instance()
# Use a broad catch-all here
except Exception:
    msg = "Failed to initialize the UploadFileHelper class"
    # Log the full stack trace, prepend a line with our message
    logger.exception(msg)


"""
Close the current neo4j connection at the end of every request
"""
@app.teardown_appcontext
def close_neo4j_driver(error):
    if hasattr(g, 'neo4j_driver_instance'):
        # Close the driver instance
        neo4j_driver.close()
        # Also remove neo4j_driver_instance from Flask's application context
        g.neo4j_driver_instance = None

# The only endpoint that should be in this file, all others should be route Blueprints...
@app.route('/', methods=['GET'])
def index():
    return "Hello! This is SenNet Ingest API service :)"

# For local development/testing
if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port")
        args = parser.parse_args()
        port = 8484
        if args.port:
            port = int(args.port)
        app.run(port=port, host='0.0.0.0')
    finally:
        pass
