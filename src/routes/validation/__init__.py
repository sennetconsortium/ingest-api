import logging
from flask import Blueprint, make_response, jsonify
import os

# begin temporary import strategy until packaged
from .ingest_validation_tools.src.validate_upload import ValidateUpload
# end temporary import strategy

validation_blueprint = Blueprint('validation', __name__)
logger = logging.getLogger(__name__)


@validation_blueprint.route('/validation')
def validate_metadata_upload():
    upload = ValidateUpload()

    fullpath = os.path.abspath('routes/validation/ingest_validation_tools/examples/dataset-examples/bad-scatacseq-data/upload/scatacseq-metadata.tsv')
    fullpath2 = os.path.abspath('routes/validation/ingest_validation_tools/examples/dataset-examples/good-scatacseq-metadata-v1/upload/metadata.tsv')
    report = upload.validate_tsvs(path=fullpath)
    # report = upload.validate_tsvs(path=fullpath2)

    data: dict = {
        "errors": True
    }
    headers: dict = {
        "Content-Type": "application/json"
    }
    return make_response(report, 200, headers)