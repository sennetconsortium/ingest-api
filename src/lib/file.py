import csv
import logging
from hubmap_commons import file_helper as commons_file_helper
from flask import current_app
from lib.rest import *
from werkzeug import utils

from routes.entity_CRUD.file_upload_helper import UploadFileHelper

logger = logging.getLogger(__name__)

# TODO: Use these methods and DRY routes.entity_CRUD

def get_csv_records(path: str):
    records = []
    headers = []
    with open(path, newline='') as tsvfile:
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

    return {
        'records': records,
        'headers': headers
    }


def get_base_path():
    return commons_file_helper.ensureTrailingSlash(current_app.config['FILE_UPLOAD_TEMP_DIR'])


def check_upload(key: str = 'file'):
    try:
        if not UploadFileHelper.is_initialized():
            file_upload_helper_instance = UploadFileHelper.create(current_app.config['FILE_UPLOAD_TEMP_DIR'],
                                                                  current_app.config['FILE_UPLOAD_DIR'],
                                                                  current_app.config['UUID_WEBSERVICE_URL'])
            logger.info('Initialized UploadFileHelper class successfully :)')
        else:
            file_upload_helper_instance = UploadFileHelper.instance()

        if key not in request.files:
            bad_request_error('No file part')

        file = request.files[key]
        if file.filename == '':
            bad_request_error('No selected file')

        file.filename = file.filename.replace(' ', '_')
        temp_id = file_upload_helper_instance.save_temp_file(file)
        file.filename = utils.secure_filename(file.filename)

        return rest_response(StatusCodes.OK, 'OK', {
            'id': temp_id,
            'file': file
        })

    except Exception as e:
        if hasattr(e, 'code'):
            return rest_response(e.code, e.name, e.description)
        else:
            return server_error(e)