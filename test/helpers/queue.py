from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(scope="function")
def job_queue():
    job_mock = MagicMock()
    job_mock.get_status.return_value = "queued"

    job_queue_mock = MagicMock()
    job_queue_mock.enqueue_job.return_value = job_mock

    with (
        patch("jobs.JobQueue.instance", return_value=job_queue_mock),
        patch("jobs.JobQueue.is_initialized", return_value=True),
    ):
        yield
