import logging
import os
import sys
from importlib import import_module
from typing import Optional, Union
from uuid import UUID, uuid4

from redis import Redis, from_url
from rq import Queue

logger: logging.Logger = logging.getLogger(__name__)

_instance = None


class TaskQueue:
    def __init__(self, url: str, queue_name: str = "default"):
        conn = from_url(url)
        self._task_queue = Queue(queue_name, connection=conn)
        self._redis = conn

    @property
    def queue(self) -> Queue:
        return self._task_queue

    @property
    def redis(self) -> Redis:
        return self._redis

    def create_queue_id(
        self, user_id: str, task_id: Optional[Union[str, UUID]] = None
    ) -> str:
        """Create a unique queue id for a user.

        This is used as the actual key for the task in the queue. We prefix the user_id
        to the task_id to ensure that the queue_id is unique for each user.

        Parameters
        ----------
        user_id : str
            The user uuid.
        task_id : Optional[Union[str, UUID]]
            The task uuid.

        Returns
        -------
        str
            The queue_id
        """
        if task_id is None:
            task_id = uuid4()
        return f"{user_id}:{task_id}"

    def split_queue_id(self, queue_id: str) -> tuple:
        """Split the queue_id into the user_id and task_id

        Parameters
        ----------
        queue_id : str
            The queue_id

        Returns
        -------
        tuple
            The user_id and task_id
        """
        user_id, task_id = queue_id.split(":")
        return user_id, task_id

    @staticmethod
    def create(url: str, queue_name: str = "default") -> None:
        global _instance
        if _instance is not None:
            raise Exception(
                "An instance of TaskQueue exists already. Use the TaskQueue.instance() method to retrieve it."
            )
        _instance = TaskQueue(url, queue_name)

    @staticmethod
    def instance() -> "TaskQueue":
        global _instance
        if _instance is None:
            raise Exception(
                "An instance of TaskQueue does not yet exist. Use TaskQueue.create(...) to create a new instance"
            )
        return _instance

    @staticmethod
    def is_initialized() -> bool:
        if _instance is None:
            return False
        return True


# Add ingest_validation_tools to the path
dir_path = os.path.dirname(__file__)
ingest_validation_tools_path = os.path.join(
    dir_path, "..", "routes", "validation", "ingest_validation_tools", "src"
)
sys.path.append(ingest_validation_tools_path)

ingest_validation_tools_upload = import_module("ingest_validation_tools.upload")
ingest_validation_tools_error_report = import_module(
    "ingest_validation_tools.error_report"
)
ingest_validation_tools_validation_utils = import_module(
    "ingest_validation_tools.validation_utils"
)
ingest_validation_tools_plugin_validator = import_module(
    "ingest_validation_tools.plugin_validator"
)
ingest_validation_tools_schema_loader = import_module(
    "ingest_validation_tools.schema_loader"
)
ingest_validation_tools_table_validator = import_module(
    "ingest_validation_tools.table_validator"
)

__all__ = [
    "ingest_validation_tools_validation_utils",
    "ingest_validation_tools_upload",
    "ingest_validation_tools_error_report",
    "ingest_validation_tools_plugin_validator",
    "ingest_validation_tools_schema_loader",
    "ingest_validation_tools_table_validator",
]
