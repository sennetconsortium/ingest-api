import logging
import os

import redis
from flask import Flask
from rq import Connection, Queue, Worker

logging.basicConfig(
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def read_config() -> dict:
    config_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "instance")
    app = Flask(__name__, instance_path=config_dir, instance_relative_config=True)
    app.config.from_pyfile("app.cfg")
    return dict(app.config)


listen_queue = ["default"]
config = read_config()

if not config.get("REDIS_MODE", False):
    raise Exception("Redis mode not enabled in config")

redis_url = config.get("REDIS_SERVER")
conn = redis.from_url(redis_url)

if __name__ == "__main__":
    with Connection(conn):
        worker = Worker(list(map(Queue, listen_queue)))
        worker.work()
