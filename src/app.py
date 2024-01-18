import os
import logging
import requests
# Don't confuse urllib (Python native library) with urllib3 (3rd-party library, requests also uses urllib3)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
from flask import Flask, g
from pymemcache import serde
from pymemcache.client.base import PooledClient

# HuBMAP commons
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons import neo4j_driver
from atlas_consortia_commons.ubkg import initialize_ubkg
from atlas_consortia_commons.rest import get_http_exceptions_classes, abort_err_handler
from atlas_consortia_commons.ubkg.ubkg_sdk import init_ontology

from routes.auth import auth_blueprint
from routes.status import status_blueprint
from routes.privs import privs_blueprint
from routes.entity_CRUD import entity_CRUD_blueprint
from routes.validation import validation_blueprint
from routes.file import file_blueprint
from routes.assayclassifier import assayclassifier_blueprint
from routes.vitessce import vitessce_blueprint

# Local Modules
from lib.file_upload_helper import UploadFileHelper
from lib.neo4j_helper import Neo4jHelper
from lib.vitessce import VitessceConfigCache

# Set logging format and level (default is warning)
# All the API logging is forwarded to the uWSGI server and gets written into the log file `uwsgi-ingest-api.log`
# Log rotation is handled via logrotate on the host system with a configuration file
# Do NOT handle log file and rotation via the Python logging to avoid issues with multi-worker processes
logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Specify the absolute path of the instance folder and use the config file relative to the instance path
app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'), instance_relative_config=True)
app.config.from_pyfile('app.cfg')

app.vitessce_cache = None
if 'MEMCACHED_MODE' in app.config:
    MEMCACHED_MODE = app.config['MEMCACHED_MODE']
    # Use prefix to distinguish the cached data of same source across different deployments
    MEMCACHED_PREFIX = app.config['MEMCACHED_PREFIX']
else:
    MEMCACHED_MODE = False
    MEMCACHED_PREFIX = 'NONE'

app.register_blueprint(auth_blueprint)
app.register_blueprint(status_blueprint)
app.register_blueprint(privs_blueprint)
app.register_blueprint(entity_CRUD_blueprint)
app.register_blueprint(validation_blueprint)
app.register_blueprint(file_blueprint)
app.register_blueprint(assayclassifier_blueprint)
app.register_blueprint(vitessce_blueprint)

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

####################################################################################################
## Memcached client initialization
####################################################################################################

memcached_client_instance = None

if MEMCACHED_MODE:
    try:
        # Use client pool to maintain a pool of already-connected clients for improved performance
        # The uwsgi config launches the app across multiple threads (8) inside each process (32), making essentially 256 processes
        # Set the connect_timeout and timeout to avoid blocking the process when memcached is slow, defaults to "forever"
        # connect_timeout: seconds to wait for a connection to the memcached server
        # timeout: seconds to wait for send or reveive calls on the socket connected to memcached
        # Use the ignore_exc flag to treat memcache/network errors as cache misses on calls to the get* methods
        # Set the no_delay flag to sent TCP_NODELAY (disable Nagle's algorithm to improve TCP/IP networks and decrease the number of packets)
        # If you intend to use anything but str as a value, it is a good idea to use a serializer
        memcached_client_instance = PooledClient(app.config['MEMCACHED_SERVER'],
                                                 max_pool_size=256,
                                                 connect_timeout=1,
                                                 timeout=30,
                                                 ignore_exc=True,
                                                 no_delay=True,
                                                 serde=serde.pickle_serde)
        app.vitessce_cache = VitessceConfigCache(memcached_client_instance, MEMCACHED_PREFIX)

        # memcached_client_instance can be instantiated without connecting to the Memcached server
        # A version() call will throw error (e.g., timeout) when failed to connect to server
        # Need to convert the version in bytes to string
        logger.info(f'Connected to Memcached server {memcached_client_instance.version().decode()} successfully :)')
    except Exception:
        msg = 'Failed to connect to the Memcached server :('
        # Log the full stack trace, prepend a line with our message
        logger.exception(msg)
        # Turn off the caching
        MEMCACHED_MODE = False

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
