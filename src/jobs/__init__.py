from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union
from uuid import UUID, uuid4

from redis import Redis, from_url
from rq import Queue

logger: logging.Logger = logging.getLogger(__name__)

_instance = None


@dataclass(frozen=True)
class JobResult:
    success: bool
    results: dict


class JobType(str, Enum):
    VALIDATE = "validate"
    REGISTER = "register"


class JobQueue:
    def __init__(self, url: str, queue_name: str = "default"):
        conn = from_url(url)
        self._job_queue = Queue(queue_name, connection=conn)
        self._redis = conn

    @property
    def queue(self) -> Queue:
        return self._job_queue

    @property
    def redis(self) -> Redis:
        return self._redis

    @staticmethod
    def create(url: str, queue_name: str = "default") -> None:
        global _instance
        if _instance is not None:
            raise Exception(
                "An instance of JobQueue exists already. Use the JobQueue.instance() method to retrieve it."
            )
        _instance = JobQueue(url, queue_name)

    @staticmethod
    def instance() -> JobQueue:
        global _instance
        if _instance is None:
            raise Exception(
                "An instance of JobQueue does not yet exist. Use JobQueue.create(...) to create a new instance"
            )
        return _instance

    @staticmethod
    def is_initialized() -> bool:
        if _instance is None:
            return False
        return True


def create_queue_id(user_id: str, job_id: Optional[Union[str, UUID]] = None) -> str:
    """Create a unique queue id for a user.

    This is used as the actual key for the job in the queue. We prefix the user_id
    to the job_id to ensure that the queue_id is unique for each user.

    Parameters
    ----------
    user_id : str
        The user uuid.
    job_id : Optional[Union[str, UUID]]
        The job uuid.

    Returns
    -------
    str
        The queue_id
    """
    if job_id is None:
        job_id = uuid4()
    return f"{user_id}:{job_id}"


def split_queue_id(queue_id: str) -> tuple:
    """Split the queue_id into the user_id and job_id

    Parameters
    ----------
    queue_id : str
        The queue_id

    Returns
    -------
    tuple
        The user_id and job_id
    """
    user_id, job_id = queue_id.split(":")
    return user_id, job_id
