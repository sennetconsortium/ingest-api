import json
import os
from test.helpers import GROUP_ID
from test.helpers.auth import AUTH_TOKEN
from test.helpers.response import mock_response
from unittest.mock import MagicMock, patch

import pytest

from jobs.validation.entities import validate_ancestor_id, validate_entity_constraints

test_data_dir = os.path.join(os.path.dirname(__file__), "data")


@pytest.fixture(scope="function", autouse=True)
def job_queue_mock():
    job_mock = MagicMock()
    job_mock.get_status.return_value = "queued"

    job_queue_mock = MagicMock()
    job_queue_mock.enqueue_job.return_value = job_mock

    with (
        patch("jobs.JobQueue.instance", return_value=job_queue_mock),
        patch("jobs.JobQueue.is_initialized", return_value=True),
    ):
        yield


# Validate Sources


@pytest.mark.parametrize(
    "entity_type, status_code",
    [
        ("source", 202),
        ("sample", 202),
        ("dataset", 202),
    ],
)
def test_validate_sources(app, entity_type, status_code):
    """Test validate sources correctly validates sources only"""

    tsv_filename = os.path.join(test_data_dir, f"test_{entity_type}.tsv")

    with open(tsv_filename, "rb") as tsv_file, app.test_client() as client:
        test_file = {
            "file": tsv_file,
            "referrer": '{"type": "validate", "path": "edit/bulk/source"}',
            "group_uuid": GROUP_ID,
        }

        res = client.post(
            "/sources/bulk/validate",
            data=test_file,
            content_type="multipart/form-data",
            buffered=True,
            headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
        )

        assert res.status_code == status_code


# Validate Samples


@pytest.mark.parametrize(
    "entity_type, status_code",
    [
        ("source", 202),
        ("sample", 202),
        ("dataset", 202),
    ],
)
def test_validate_samples(app, entity_type, status_code):
    """Test validate samples correctly validates samples only"""
    tsv_filename = os.path.join(test_data_dir, f"test_{entity_type}.tsv")

    with open(tsv_filename, "rb") as tsv_file, app.test_client() as client:
        test_file = {
            "file": tsv_file,
            "referrer": '{"type": "validate", "path": "edit/bulk/sample"}',
            "group_uuid": GROUP_ID,
        }

        res = client.post(
            "/samples/bulk/validate",
            data=test_file,
            content_type="multipart/form-data",
            buffered=True,
            headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
        )

        assert res.status_code == status_code


# Validate Entity Constraints


@pytest.mark.parametrize(
    "name",
    [
        "file_valid_entity_returns_200",
        "file_invalid_entity_returns_200",
        "file_valid_entity_returns_400",
        "file_invalid_entity_returns_400",
    ],
)
def test_validate_entity_constraints(app, requests, name):
    """Test validate entity constraints returns the correct response"""

    with open(os.path.join(test_data_dir, "validate_entity_constraints.json"), "r") as f:
        test_data = json.load(f)[name]

    file_is_valid, error_msg, post_response, expected_result = test_data.values()

    # post_response is structured as (status_code, json_data)
    entity_api_url = app.config["ENTITY_WEBSERVICE_URL"]
    requests.add_response(
        f"{entity_api_url}/constraints?match=true&report_type=ln_err",
        "post",
        mock_response(*post_response),
    )

    # post_response is structured as (status_code, json_data)
    with (
        app.app_context(),
        # patch("requests.post", return_value=test_utils.create_response(*post_response)),
    ):

        result = validate_entity_constraints(file_is_valid, error_msg, {}, [])

        assert result == expected_result


# Validate Ancestor Id


@pytest.mark.parametrize("name", ["valid_ancestor_id", "failing_uuid_response", "ancestor_saved"])
def test_validate_ancestor_id(app, requests, name):
    """Test validate ancestor id returns the correct response"""

    with open(os.path.join(test_data_dir, "validate_ancestor_id.json"), "r") as f:
        test_data = json.load(f)[name]

    (
        ancestor_id,
        error_msg,
        valid_ancestor_ids,
        file_is_valid,
        get_response,
        expected_result,
    ) = test_data.values()

    uuid_api_url = app.config["UUID_WEBSERVICE_URL"]
    requests.add_response(
        f"{uuid_api_url}/uuid/{ancestor_id}",
        "get",
        mock_response(*get_response),
    )

    with app.app_context():
        result = validate_ancestor_id(
            {},
            ancestor_id,
            error_msg,
            1,
            valid_ancestor_ids,
            file_is_valid,
        )

        assert result == expected_result
