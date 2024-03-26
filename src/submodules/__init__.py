import os
import sys

dir_path = os.path.dirname(__file__)

# Add ingest_validation_tools to the path
# use 'import ingest_validation_tools' to import the package
ingest_validation_tools_path = os.path.join(dir_path, "ingest_validation_tools", "src")
sys.path.append(ingest_validation_tools_path)
