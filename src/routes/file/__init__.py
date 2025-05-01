from flask import Blueprint, jsonify, request, current_app
from werkzeug.utils import secure_filename
from shutil import rmtree
from pathlib import Path
import os
import logging

from lib.file_upload_helper import UploadFileHelper
from lib.request_validation import get_validated_uuids, is_uuid
from atlas_consortia_commons.rest import *

file_blueprint = Blueprint('file', __name__)
logger: logging.Logger = logging.getLogger(__name__)


def get_upload_file_helper_instance() -> UploadFileHelper:
    try:
        if UploadFileHelper.is_initialized() is False:
            logger.info("Creating UploadFileHelper class")
            return UploadFileHelper.create(current_app.config['FILE_UPLOAD_TEMP_DIR'],
                                           current_app.config['FILE_UPLOAD_DIR'],
                                           current_app.config['UUID_WEBSERVICE_URL'])
        return UploadFileHelper.instance()
    except Exception:
        msg = "Failed to initialize the UploadFileHelper class"
        logger.exception(msg)
        abort_internal_err(msg)


"""
File upload handling for Source and Sample

Returns
-------
json
    A JSON containing the temp file id
"""


@file_blueprint.route('/file-upload', methods=['POST'])
def upload_file():
    # Check if the post request has the file part
    if 'file' not in request.files:
        abort_bad_req('No file part')

    file = request.files['file']

    if file.filename == '':
        abort_bad_req('No selected file')

    try:
        file_upload_helper_instance: UploadFileHelper = get_upload_file_helper_instance()
        temp_id = file_upload_helper_instance.save_temp_file(file)
        rspn_data = {
            "temp_file_id": temp_id
        }

        return jsonify(rspn_data), 201
    except Exception:
        # Log the full stack trace, prepend a line with our message
        msg = "Failed to upload files"
        logger.exception(msg)
        abort_internal_err(msg)


"""
File commit triggered by entity-api trigger method for Source/Sample/Dataset

Source: image files
Sample: image files and thumbnails
Dataset: only the one thumbnail file

This call also creates the symbolic link from the file uuid dir under uploads
to the assets dir so the uploaded files can be exposed via the file assets service

Returns
-------
json
    A JSON containing the file uuid info
"""


@file_blueprint.route('/file-commit', methods=['POST'])
def commit_file():
    # Always expect a json body
    require_json(request)

    # Parse incoming json string into json data(python dict object)
    json_data_dict = request.get_json()

    file_upload_helper_instance: UploadFileHelper = get_upload_file_helper_instance()

    entity_uuid = secure_filename(json_data_dict['entity_uuid'])
    if not is_uuid(entity_uuid):
        abort_bad_req(f"Invalid entity uuid: {entity_uuid}")

    temp_file_id = secure_filename(json_data_dict['temp_file_id'])
    if not file_upload_helper_instance.validate_temp_file_id(temp_file_id):
        abort_bad_req(f"Invalid temp file id: {temp_file_id}")

    user_token = json_data_dict['user_token']

    file_uuid_info = file_upload_helper_instance.commit_file(temp_file_id, entity_uuid, user_token)
    filename = secure_filename(file_uuid_info['filename'])
    file_uuid = secure_filename(file_uuid_info['file_uuid'])

    # Link the uploaded file uuid dir to assets
    # /hive/hubmap/hm_uploads/<entity_uuid>/<file_uuid>/<filename> (for PROD)
    source_file_path = os.path.join(str(current_app.config['FILE_UPLOAD_DIR']), entity_uuid, file_uuid, filename)
    # /hive/hubmap/assets/<file_uuid>/<filename> (for PROD)
    target_file_dir = os.path.join(str(current_app.config['SENNET_WEBSERVICE_FILEPATH']), file_uuid)
    target_file_path = os.path.join(target_file_dir, filename)

    # Create the file_uuid directory under assets dir
    # and a symbolic link to the uploaded file
    try:
        Path(target_file_dir).mkdir(parents=True, exist_ok=True)
        os.symlink(source_file_path, target_file_path)
    except Exception:
        logger.exception(f"Failed to create the symbolic link from {source_file_path} to {target_file_path}")

    # Send back the updated file_uuid_info
    return jsonify(file_uuid_info)


"""
File removal triggered by entity-api trigger method for Source/Sample/Dataset
during entity update

Source: image files
Sample: image files and thumbnails

Returns
-------
json
    A JSON list containing the updated files info
    It's an empty list for Dataset since there's only one thumbnail file
"""


@file_blueprint.route('/file-remove', methods=['POST'])
def remove_file():
    # Always expect a json body
    require_json(request)

    # Parse incoming json string into json data(python dict object)
    json_data_dict = request.get_json()

    entity_uuid = secure_filename(json_data_dict['entity_uuid'])
    if not is_uuid(entity_uuid):
        abort_bad_req(f"Invalid entity uuid: {entity_uuid}")

    try:
        file_uuids = [secure_filename(file_uuid) for file_uuid in json_data_dict['file_uuids']]
        file_uuids = get_validated_uuids(file_uuids)
    except ValueError:
        abort_bad_req(f"Invalid file uuids: {json_data_dict['file_uuids']}")

    files_info_list = json_data_dict['files_info_list']

    file_upload_helper_instance: UploadFileHelper = get_upload_file_helper_instance()
    # `upload_dir` is already normalized with trailing slash
    entity_upload_dir = file_upload_helper_instance.upload_dir + entity_uuid + os.sep

    # Remove the physical files from the file system
    for file_uuid in file_uuids:
        # Get back the updated files_info_list
        files_info_list = file_upload_helper_instance.remove_file(entity_upload_dir, file_uuid, files_info_list)

        # Also remove the dir contains the symlink to the uploaded file under assets
        # /hive/hubmap/assets/<file_uuid> (for PROD)
        assets_file_dir = os.path.join(str(current_app.config['SENNET_WEBSERVICE_FILEPATH']), file_uuid)
        # Delete an entire directory tree
        # path must point to a directory (but not a symbolic link to a directory)
        rmtree(assets_file_dir)

    # Send back the updated files_info_list
    return jsonify(files_info_list)


def require_json(request):
    if not request.is_json:
        abort_bad_req("A json body and appropriate Content-Type header are required")
