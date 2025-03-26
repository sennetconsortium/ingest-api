FROM sennet/api-base-image:1.2.1
ENV LANG=en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

LABEL description="SenNet Ingest API RQ Service"

# Specify the Python version to be installed. Default is 3.11.
# Override with --build-arg PYTHON_VERSION=3.12 or args: PYTHON_VERSION=3.12 in docker-compose
# Note: RHEL only has certain versions of Python available. If the version is not available, the build will fail.
ARG PYTHON_VERSION=3.11

# Output right away
ENV PYTHONUNBUFFERED 1

WORKDIR /usr/src/app

# Copy from host to image
COPY .. .

RUN groupadd -r -g 100008 codcc && \
    useradd -r -u 100008 -g 100008 -m codcc && \
    python${PYTHON_VERSION} -m pip install --upgrade pip && \
    python${PYTHON_VERSION} -m pip install -r ./src/requirements.txt && \
    python${PYTHON_VERSION} -m pip install -r ./src/submodules/ingest_validation_tools/requirements.txt

USER codcc

CMD ["python${PYTHON_VERSION}", "src/worker.py"]
