import os
from array import array

import yaml
import requests
import logging
from flask import Flask
import urllib.request
from pathlib import Path
from shutil import copy2
from hubmap_commons.exceptions import HTTPException
from hubmap_sdk import EntitySdk, SearchSdk

# Suppress InsecureRequestWarning warning when requesting status on https with ssl cert verify disabled
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logger = logging.getLogger(__name__)

# In Python, "privacy" depends on "consenting adults'" levels of agreement, we can't force it.
# A single leading underscore means you're not supposed to access it "from the outside"
_entity_api_url = None
_search_api_url = None


def load_flask_instance_config():
    # Specify the absolute path of the instance folder and use the config file relative to the instance path
    app = Flask(__name__,
                instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'),
                instance_relative_config=True)
    app.config.from_pyfile('app.cfg')

    return app.config


class DatasetHelper:

    def __init__(self):
        # Specify as module-scope variables
        global _entity_api_url
        global _search_api_url

        if _entity_api_url is None:
            config = load_flask_instance_config()
            _entity_api_url = config['ENTITY_WEBSERVICE_URL']
            _search_api_url = config['SEARCH_WEBSERVICE_URL']

    def get_organ_types_dict(self) -> object:
        yaml_file_url = 'https://raw.githubusercontent.com/hubmapconsortium/search-api/main/src/search-schema/data/definitions/enums/organ_types.yaml'
        with urllib.request.urlopen(yaml_file_url) as response:
            yaml_file = response.read()
            try:
                return yaml.safe_load(yaml_file)
            except yaml.YAMLError as e:
                raise yaml.YAMLError(e)

    # This is the business logic for `/datasets/<uuid>/verifytitleinfo` endpoint that is used by
    # the ingest-validation-tests package to validate the data needed to produce a title
    # Note: the `title` is generated by entity-api using a on_read_trigger
    # here is one uuid that actually pass validation requirements: ead5cc01250b4f9ea73dd91503c313a5
    def verify_dataset_title_info(self, dataset_uuid: str, user_token: str) -> array:
        entity_api = EntitySdk(token=user_token, service_url=_entity_api_url)
        search_api = SearchSdk(token=user_token, service_url=_search_api_url)

        data_found = {'age': False, 'race': False, 'sex': False}
        rslt = []

        try:
            entity = entity_api.get_entity_by_id(dataset_uuid)
        except Exception:
            rslt.append(f'Unable to get the target dataset with uuid: {dataset_uuid}')
            return rslt
        dataset = vars(entity)

        if 'data_types' in dataset:
            for data_type in dataset['data_types']:
                try:
                    search = search_api.assayname(data_type)
                except:
                    rslt.append(f"Unable to query the assay type details of: {data_type} via search-api")
        else:
            rslt.append('The dataset did not contain a ''data_types'' key')

        # TO-DO: the blow logic can be simplified by parsing the `title` field returned by entity-api - Zhou
        try:
            entity = entity_api.get_ancestors(dataset['uuid'])
        except Exception:
            rslt.append(f"Unable to get the ancestors of dataset with uuid: {dataset_uuid}")
        for ancestor in entity:
            ancestor_dict = vars(ancestor)
            if 'entity_type' in ancestor_dict:
                if ancestor_dict['entity_type'] == 'Sample':
                    if 'sample_category' in ancestor_dict and ancestor_dict['sample_category'].lower() == 'organ':
                        if 'organ' in ancestor_dict:
                            organ_code = ancestor_dict['organ']
                            organ_types_dict = self.get_organ_types_dict()
                            if organ_code in organ_types_dict:
                                organ_entry = organ_types_dict[organ_code]
                                if organ_entry is None or 'description' not in organ_entry:
                                    rslt.append(f"Description for Organ code '{organ_code}' not found in organ types file")
                            else:
                                rslt.append(f"Organ code '{organ_code}' not found in organ types file")
                        else:
                            rslt.append('Organ key not found in sample_category organ')

                elif ancestor_dict['entity_type'] == 'Donor':
                    try:
                        for data in ancestor_dict['metadata']['organ_donor_data']:
                            if data['grouping_concept_preferred_term'].lower() == 'age':
                                data_found['age'] = True

                            if data['grouping_concept_preferred_term'].lower() == 'race':
                                data_found['race'] = True

                            if data['grouping_concept_preferred_term'].lower() == 'sex':
                                data_found['sex'] = True
                    except KeyError:
                        pass

        for k, v in data_found.items():
            if not v:
                rslt.append(f'Donor metadata.organ_donor_data grouping_concept_preferred_term {k} not found')

        return rslt


    # Added by Zhou for handling dataset thumbnail file
    # - delete exisiting 'thumbnail_file' via entity-api if already exists
    # - copy the original thumbnail file to upload temp dir
    def handle_thumbnail_file(self, thumbnail_file_abs_path: str, entity_api: EntitySdk, dataset_uuid: str,
                              extra_headers: dict, temp_file_id: str, file_upload_temp_dir: str):
        # Delete the old thumbnail file from Neo4j before updating with new one
        # First retrieve the exisiting thumbnail file uuid
        try:
            entity = entity_api.get_entity_by_id(dataset_uuid)
        # All exceptions that occur in EntitySdk are HTTPExceptions
        except HTTPException as e:
            err_msg = f"Failed to query the dataset of uuid {dataset_uuid} while calling EntitySdk.get_entities() status code:{e.status_code}  message:{e.description}"
            logger.error(err_msg)
            # Bubble up the error message
            raise requests.exceptions.RequestException(err_msg)

        entity_dict = vars(entity)

        logger.debug('=======EntitySdk.get_entity_by_id() resulting entity_dict=======')
        logger.debug(entity_dict)

        # Easier to ask for forgiveness than permission (EAFP)
        # Rather than checking key existence at every level
        try:
            thumbnail_file_uuid = entity_dict['thumbnail_file']['file_uuid']

            # To remove the existing thumbnail file, just pass the file uuid as a string
            put_data = {
                'thumbnail_file_to_remove': thumbnail_file_uuid
            }
            entity_api.header.update(extra_headers)
            try:
                entity = entity_api.update_entity(dataset_uuid, put_data)
            # All exceptions that occur in EntitySdk are HTTPExceptions
            except HTTPException as e:
                err_msg = f"Failed to remove the existing thumbnail file for dataset of uuid {dataset_uuid} while calling EntitySdk.put_entities() status code:{e.status_code}  message:{e.description}"
                logger.error(err_msg)
                # Bubble up the error message
                raise requests.exceptions.RequestException(err_msg)

            logger.info(f"Successfully removed the existing thumbnail file of the dataset uuid {dataset_uuid}")
        except KeyError:
            logger.info(f"No existing thumbnail file found for the dataset uuid {dataset_uuid}")
            pass

        entity_dict = vars(entity)

        logger.debug('=======EntitySdk.update_entity() resulting entity_dict=======')
        logger.debug(entity_dict)

        # Create the temp file dir under the temp uploads for the thumbnail
        # /hive/hubmap/hm_uploads_tmp/<temp_file_id> (for PROD)
        temp_file_dir = os.path.join(file_upload_temp_dir, temp_file_id)

        try:
            Path(temp_file_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.exception(f"Failed to create the thumbnail temp upload dir {temp_file_dir} for thumbnail file attched to Dataset {dataset_uuid}")

        # Then copy the source thumbnail file to the temp file dir
        # shutil.copy2 is identical to shutil.copy() method
        # but it also try to preserves the file's metadata
        copy2(thumbnail_file_abs_path, temp_file_dir)
