import json
import os
from unittest.mock import patch

import pytest

import app as app_module
from routes.entity_CRUD import validate_ancestor_id, validate_entity_constraints
import test.utils as test_utils

test_data_dir = os.path.join(os.path.dirname(__file__), 'data')

@pytest.fixture()
def app():
    app = app_module.app
    app.config.update({
        'TESTING': True,
        'UUID_WEBSERVICE_URL': 'http://uuid-api:7000/',
        'ENTITY_WEBSERVICE_URL': 'http://entity-api:7000/',
    })
    # other setup
    yield app
    # clean up

@pytest.fixture(scope="session", autouse=True)
def ontology_mock():
    """Automatically add ontology mock functions to all tests"""
    with (patch('atlas_consortia_commons.ubkg.ubkg_sdk.UbkgSDK', new=test_utils.MockOntology)):
        yield   

# Validate Sources

@pytest.mark.parametrize('entity_type, status_code', [
    ('source', 200),
    ('sample', 400),
    ('dataset', 400),
])
def test_validate_sources(app, entity_type, status_code):
    """Test validate sources correctly validates sources only"""

    with open(os.path.join(test_data_dir, f'{entity_type}.json'), 'r') as f:
        test_data = json.load(f)

    tsv_filename = os.path.join(test_data_dir, f'test_{entity_type}.tsv')

    with (open(tsv_filename, 'rb') as tsv_file,
          app.test_client() as client):
        
        test_file = { 'file': (tsv_file, tsv_filename) }

        res = client.post('/sources/bulk/validate',
                          data=test_file,
                          content_type='multipart/form-data',
                          buffered=True,
                          headers=test_data['header'])

        assert res.status_code == status_code

# Validate Samples

@pytest.mark.parametrize('entity_type, status_code', [
    ('source', 400),
    ('sample', 200),
    ('dataset', 400),
])
def test_validate_samples(app, entity_type, status_code):
    """Test validate samples correctly validates samples only"""

    with open(os.path.join(test_data_dir, f'{entity_type}.json'), 'r') as f:
        test_data = json.load(f)

    tsv_filename = os.path.join(test_data_dir, f'test_{entity_type}.tsv')

    def get_responses():
        if not test_data.get('ancestor_response'):
            return None
        return [test_utils.create_response(200, i) for i in test_data['ancestor_response']]

    with (open(tsv_filename, 'rb') as tsv_file,
          app.test_client() as client,
          patch('requests.get', side_effect=get_responses()),
          patch('requests.post', return_value=test_utils.create_response(200))):

        test_file = { 'file': (tsv_file, tsv_filename) }

        res = client.post('/samples/bulk/validate',
                          data=test_file,
                          content_type='multipart/form-data',
                          buffered=True,
                          headers=test_data['header'])

        assert res.status_code == status_code

# Validate Datasets

@pytest.mark.parametrize('entity_type, status_code', [
    ('source', 400),
    ('sample', 400),
    ('dataset', 200),
])
def test_validate_datasets(app, entity_type, status_code):
    """Test validate datasets correctly validates datasets only"""

    with open(os.path.join(test_data_dir, f'{entity_type}.json'), 'r') as f:
        test_data = json.load(f)

    tsv_filename = os.path.join(test_data_dir, f'test_{entity_type}.tsv')

    def get_responses():
        if not test_data.get('ancestor_response'):
            return None
        return [test_utils.create_response(200, i) for i in test_data['ancestor_response']]

    with (open(tsv_filename, 'rb') as tsv_file,
          app.test_client() as client,
          patch('requests.get', side_effect=get_responses()),
          patch('requests.post', return_value=test_utils.create_response(200))):

        test_file = { 'file': (tsv_file, tsv_filename) }

        res = client.post('/datasets/bulk/validate',
                          data=test_file,
                          content_type='multipart/form-data',
                          buffered=True,
                          headers=test_data['header'])

        assert res.status_code == status_code

# Validate Entity Constraints

@pytest.mark.parametrize('name', [
    'file_valid_entity_returns_200',
    'file_invalid_entity_returns_200',
    'file_valid_entity_returns_400',
    'file_invalid_entity_returns_400'
])
def test_validate_entity_constraints(app, name):
    """Test validate entity constraints returns the correct response"""

    with open(os.path.join(test_data_dir, 'validate_entity_constraints.json'), 'r') as f:
        test_data = json.load(f)[name]

    file_is_valid, error_msg, post_response, expected_result  = test_data.values()

    # post_response is structured as (status_code, json_data)
    with (app.app_context(),
          patch('requests.post', return_value=test_utils.create_response(*post_response))):
        
        result = validate_entity_constraints(file_is_valid, error_msg, {}, [])

        assert result == expected_result

# Validate Ancestor Id

@pytest.mark.parametrize('name', [
    'valid_ancestor_id',
    'failing_uuid_response',
    'ancestor_saved'
])
def test_validate_ancestor_id(app, name):
    """Test validate ancestor id returns the correct response"""

    with open(os.path.join(test_data_dir, 'validate_ancestor_id.json'), 'r') as f:
        test_data = json.load(f)[name]

    ancestor_id, error_msg, valid_ancestor_ids, file_is_valid, get_response, expected_result  = test_data.values()

    with (app.app_context(),
          patch('requests.get', return_value=test_utils.create_response(*get_response))):
        
        result = validate_ancestor_id({}, ancestor_id, error_msg, 1, valid_ancestor_ids, file_is_valid)

        assert result == expected_result
