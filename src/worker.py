import logging
import os

from atlas_consortia_commons.rest import abort_err_handler, get_http_exceptions_classes
from atlas_consortia_commons.ubkg import initialize_ubkg
from atlas_consortia_commons.ubkg.ubkg_sdk import init_ontology
from flask import Flask
from redis import from_url as redis_from_url
from rq import Connection, Queue, Worker

logging.basicConfig(
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

listen_queue = ["default"]

config_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "instance")
app = Flask(__name__, instance_path=config_dir, instance_relative_config=True)
app.config.from_pyfile("app.cfg")

if not app.config.get("REDIS_MODE", False):
    raise Exception("Redis mode not enabled in config")

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

redis_url = app.config.get("REDIS_SERVER")
conn = redis_from_url(redis_url)

if __name__ == "__main__":
    with Connection(conn), app.app_context():
        worker = Worker(list(map(Queue, listen_queue)))
        worker.work()
