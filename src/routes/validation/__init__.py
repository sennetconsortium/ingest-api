import logging
import os
from flask import Blueprint, make_response, request, abort, current_app
from hubmap_commons import file_helper as commons_file_helper
from werkzeug import utils

from routes.entity_CRUD.file_upload_helper import UploadFileHelper
from .ingest_validation_tools.src.validate_upload import ValidateUpload

validation_blueprint = Blueprint('validation', __name__)
logger = logging.getLogger(__name__)


def bad_request_error(err_msg):
    abort(400, description = err_msg)


def check_upload():
    file = None
    result: dict = {
        'error': None
    }
    try:
        if not UploadFileHelper.is_initialized():
            file_upload_helper_instance = UploadFileHelper.create(current_app.config['FILE_UPLOAD_TEMP_DIR'],
                                                                  current_app.config['FILE_UPLOAD_DIR'],
                                                                  current_app.config['UUID_WEBSERVICE_URL'])
            logger.info("Initialized UploadFileHelper class successfully :)")
        else:
            file_upload_helper_instance = UploadFileHelper.instance()

        key = 'metadata'
        if key not in request.files:
            bad_request_error('No file part')
        file = request.files[key]
        if file.filename == '':
            bad_request_error('No selected file')

        file.filename = file.filename.replace(" ", "_")
        temp_id = file_upload_helper_instance.save_temp_file(file)
        file.filename = utils.secure_filename(file.filename)
        base_path = commons_file_helper.ensureTrailingSlash(current_app.config['FILE_UPLOAD_TEMP_DIR'])
        result['location'] = base_path + temp_id + os.sep + file.filename
        result['file'] = file
    except Exception as e:
        result['error'] = {
            'code': e.code,
            'name': e.name,
            'description': e.description
        }
        print(e)
    return result


@validation_blueprint.route('/validation', methods=['POST'])
def validate_metadata_upload():

    upload = check_upload()
    error = upload['error']
    response = error
    if error is None:
        validator = ValidateUpload()
        validation_results = validator.validate_tsvs(path=upload['location'])
        if validation_results is not None:
            response = {
                'code': 406,
                'description': validation_results
            }
        else:
            response = {
                'code': 200
            }

    headers: dict = {
        "Content-Type": "application/json"
    }
    return make_response(response, response['code'], headers)