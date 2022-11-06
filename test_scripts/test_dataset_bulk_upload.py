import json
import sys
import os
import csv
from unittest import TestCase, main
from unittest.mock import Mock, patch

from flask import current_app, Flask
filepath = os.path.abspath(__file__)
parentpath = os.path.dirname(os.path.dirname(filepath))
srcpath = f'{parentpath}/src'
sys.path.append(srcpath)
import app
from routes import entity_CRUD

class Test_Entity_Crud(TestCase):
    def setUp(self):
        app.app.testing = True
        self.app = app.app.test_client()
        ctx = app.app.app_context()
        ctx.push()

    # @patch.object(requests, 'get')
    # def test_test(self, mock_requests):
    #     # mock_requests.return_value = json.dumps('{"test": "value"')
    #     mock_requests.json().return_value = json.dumps('"test": "value"')
    #     result = self.app.post('/test')
    #     print(result.json)
    #     mock_requests.assert_called()

########################################################################################################################
    # Test datasets/bulk-upload
########################################################################################################################

    #@patch.object(requests, 'get')
    # @patch.object(entity_CRUD, 'validate_datasets')
    # def test_bulk_dataset_upload_happy_path(self, mock_requests):
    #     mock_requests.return_value = True
    #     data = {'file': open('sennet_datasets_good.tsv', 'rb')}
    #     headers = {'Authorization': 'Bearer 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
    #     result = self.app.post('/datasets/bulk-upload', data=data, follow_redirects=True, content_type='multipart/form-data', headers=headers)
    #     mock_requests.assert_called()
    #     self.assertEqual(result.status_code, 201)
    #
    # @patch.object(entity_CRUD, 'validate_datasets')
    # def test_bulk_dataset_upload_unhappy_path(self, mock_requests):
    #     mock_requests.return_value = ['Row Number: 1. Unable to verify ancestor_id exists', 'Row Number: 2. Unable to verify ancestor_id exists', "Row Number: 2. has_gene_sequences must be 'true' or 'false'", 'Row Number: 3. Unable to verify ancestor_id exists', 'Row Number: 4. Unable to verify ancestor_id exists', 'Row Number: 4. data_type value must be an assay type listed in assay type files (https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml)', 'Row Number: 5. Unable to verify ancestor_id exists', 'Row Number: 5. lab_id must be fewer than 1024 characters', 'Row Number: 6. Description must be fewer than 10,000 characters', 'Row Number: 6. Unable to verify ancestor_id exists']
    #     data = {'file': open('sennet_datasets_bad_data.tsv', 'rb')}
    #     headers = {'Authorization': 'Bearer 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
    #     result = self.app.post('/datasets/bulk-upload', data=data, follow_redirects=True, content_type='multipart/form-data', headers=headers)
    #     mock_requests.assert_called()
    #     self.assertEqual(result.status_code, 400)
    #     self.assertEqual(result.get_json(), {"data": {"0": "Row Number: 1. Unable to verify ancestor_id exists", "1": "Row Number: 2. Unable to verify ancestor_id exists", "2": "Row Number: 2. has_gene_sequences must be 'true' or 'false'", "3": "Row Number: 3. Unable to verify ancestor_id exists", "4": "Row Number: 4. Unable to verify ancestor_id exists", "5": "Row Number: 4. data_type value must be an assay type listed in assay type files (https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml)", "6": "Row Number: 5. Unable to verify ancestor_id exists", "7": "Row Number: 5. lab_id must be fewer than 1024 characters", "8": "Row Number: 6. Description must be fewer than 10,000 characters", "9": "Row Number: 6. Unable to verify ancestor_id exists"}, "status": "fail"})
    #

########################################################################################################################
    # Test Validate Datasets
########################################################################################################################
    #@patch.object(entity_CRUD.request, 'get')
    def test_bulk_dataset_upload_happy_path(self):
        #mock_requests.json().return_value = json.dumps('"uuid": "11111111111111111111111111111111"')
        #mock_requests.status_code = 201
        headers = []
        records = []
        header = {'Authorization': 'Bearer 11111111111111111111111111111111'}
        with open('sennet_datasets_good.tsv', newline='') as tsvfile:
            reader = csv.DictReader(tsvfile, delimiter='\t')
            first = True
            for row in reader:
                data_row = {}
                for key in row.keys():
                    if first:
                        headers.append(key)
                    data_row[key] = row[key]
                records.append(data_row)
                if first:
                    first = False
        for record in records:
            if record.get('ancestor_id'):
                ancestor_id_string = record['ancestor_id']
                ancestor_id_list = ancestor_id_string.split(',')
                if isinstance(ancestor_id_list, str):
                    ancestor_id_list = [ancestor_id_list]
                ancestor_stripped = []
                for ancestor in ancestor_id_list:
                    ancestor_stripped.append(ancestor.strip())
                record['ancestor_id'] = ancestor_stripped
            if record.get('data_types'):
                data_types_string = record['data_types']
                data_types_list = data_types_string.split(',')
                data_type_stripped = []
                for data_type in data_types_list:
                    data_type_stripped.append(data_type.strip())
                record['data_types'] = data_type_stripped
            if record.get('human_gene_sequences'):
                gene_sequences_string = record['human_gene_sequences']
                if gene_sequences_string.lower() == "true":
                    record['human_gene_sequences'] = True
                if gene_sequences_string.lower() == "false":
                    record['human_gene_sequences'] = False
        result = entity_CRUD.validate_datasets(headers, records, header)
        #mock_requests.assert_called()
        self.assertEqual(result, True)

    # @patch.object(app.requests, 'get')
    # def test_bulk_dataset_bad_fields(self, mock_requests):
    #     mock_requests.json().return_value = json.dumps('"uuid": "11111111111111111111111111111111"')
    #     mock_requests.status_code = 201
    #     data = {'file': open('sennet_datasets_bad_headers.tsv', 'rb')}
    #     headers = {
    #         'Authorization': 'Bearer 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
    #     result = self.app.post('/datasets/bulk-upload', data=data, follow_redirects=True,
    #                            content_type='multipart/form-data', headers=headers)
    #     self.assertEqual(result.status_code, 400)
    #     data = {"0": "lab_id is a required field", "1": "data_types is a required field",
    #             "2": "lab_id1 is not an accepted field", "3": "data_types2 is not an accepted field"}
    #     output = result.json['data']
    #     self.assertEqual(output, data)
    #
    # @patch.object(app.requests, 'get')
    # def test_bulk_dataset_too_many_fields(self, mock_requests):
    #     mock_requests.json().return_value = json.dumps('"uuid": "11111111111111111111111111111111"')
    #     mock_requests.status_code = 201
    #     data = {'file': open('sennet_datasets_too_many_headers.tsv', 'rb')}
    #     headers = {
    #         'Authorization': 'Bearer 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
    #     result = self.app.post('/datasets/bulk-upload', data=data, follow_redirects=True,
    #                            content_type='multipart/form-data', headers=headers)
    #     self.assertEqual(result.status_code, 400)
    #     data = {"0": " is not an accepted field"}
    #     output = result.json['data']
    #     self.assertEqual(output, data)
    #
    # @patch.object(app.requests, 'get')
    # def test_bulk_dataset_too_many_fields(self, mock_requests):
    #     mock_requests.json().return_value = json.dumps('"uuid": "11111111111111111111111111111111"')
    #     mock_requests.status_code = 201
    #     data = {'file': open('sennet_datasets_too_few_headers.tsv', 'rb')}
    #     headers = {
    #         'Authorization': 'Bearer 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
    #     result = self.app.post('/datasets/bulk-upload', data=data, follow_redirects=True,
    #                            content_type='multipart/form-data', headers=headers)
    #     self.assertEqual(result.status_code, 400)
    #     data = {"0": "human_gene_sequences is a required field", "1": "data_types is a required field",
    #             "2": "human_gene_sequences data_types is not an accepted field"}
    #     output = result.json['data']
    #     self.assertEqual(output, data)
    #
    # @patch.object(app.requests, 'get')
    # def test_bulk_dataset_too_many_columns(self, mock_requests):
    #     mock_requests.json().return_value = json.dumps('"uuid": "11111111111111111111111111111111"')
    #     mock_requests.status_code = 201
    #     data = {'file': open('sennet_datasets_too_many_columns.tsv', 'rb')}
    #     headers = {
    #         'Authorization': 'Bearer 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
    #     result = self.app.post('/datasets/bulk-upload', data=data, follow_redirects=True,
    #                            content_type='multipart/form-data', headers=headers)
    #     self.assertEqual(result.status_code, 400)
    #     data = {
    #         "0": "Row Number: 1. This row has too many entries. Check file; verify that there are are only as many fields as there are headers",
    #         "1": "Row Number: 1. This row has too many entries. Check file; verify that there are are only as many fields as there are headers"
    #     }
    #     output = result.json['data']
    #     self.assertEqual(output, data)
    #
    # @patch.object(app.requests, 'get')
    # def test_bulk_datasets_too_few_columns(self, mock_requests):
    #     mock_requests.json().return_value = json.dumps('"uuid": "11111111111111111111111111111111"')
    #     mock_requests.status_code = 201
    #     data = {'file': open('sennet_datasets_too_few_columns.tsv', 'rb')}
    #     headers = {
    #         'Authorization': 'Bearer 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
    #     result = self.app.post('/datasets/bulk-upload', data=data, follow_redirects=True,
    #                            content_type='multipart/form-data', headers=headers)
    #     self.assertEqual(result.status_code, 400)
    #     data = {
    #         "0": "Row Number: 1. This row has too few entries. Check file; verify spaces were not used where a tab should be",
    #         "1": "Row Number: 1. This row has too few entries. Check file; verify spaces were not used where a tab should be"
    #     }
    #     output = result.json['data']
    #     self.assertEqual(output, data)
    #
    # @patch.object(app.requests, 'get')
    # def test_bulk_datasets_bad_data(self, mock_requests):
    #     mock_requests.json().return_value = json.dumps('"uuid": "11111111111111111111111111111111"')
    #     mock_requests.status_code = 201
    #     data = {'file': open('sennet_datasets_bad_data.tsv', 'rb')}
    #     headers = {
    #         'Authorization': 'Bearer 1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'}
    #     result = self.app.post('/datasets/bulk-upload', data=data, follow_redirects=True,
    #                            content_type='multipart/form-data', headers=headers)
    #     self.assertEqual(result.status_code, 400)
    #     data = {
    #         "0": "Row Number: 2. has_gene_sequences must be 'true' or 'false'",
    #         "1": "Row Number: 4. data_type value must be an assay type listed in assay type files (https://raw.githubusercontent.com/sennetconsortium/search-api/main/src/search-schema/data/definitions/enums/assay_types.yaml)",
    #         "2": "Row Number: 5. lab_id must be fewer than 1024 characters",
    #         "3": "Row Number: 6. Description must be fewer than 10,000 characters"
    #     }
    #     output = result.json['data']
    #     self.assertEqual(output, data)

if __name__ == '__main__':
    main()


