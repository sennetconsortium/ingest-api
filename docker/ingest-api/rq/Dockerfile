FROM sennet/api-base-image:1.3.1

LABEL description="SenNet Ingest API RQ Service"

ARG HOST_GID
ARG HOST_UID

# Change to directory that contains the Dockerfile
WORKDIR /usr/src/app

EXPOSE 5000 8080

USER root

# Copy from host to image
COPY .. .

# Update outdated packages and install Python packages
RUN apt-get update -y && \
    apt-get dist-upgrade -y && \
    sed -i '/^git+https/d' ./src/requirements.txt && \
    pip install --upgrade pip setuptools wheel && \
    pip install -r ./src/requirements.txt && \
    pip install -r ./src/submodules/ingest_validation_tools/requirements.txt

# Modify the UID and GID of codcc to match the host
RUN groupmod --gid $HOST_GID codcc && \
    usermod --uid $HOST_UID codcc && \
    chown -R codcc:codcc /usr/src/app 

USER codcc

ENTRYPOINT ["python", "src/worker.py"]
