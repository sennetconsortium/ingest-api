FROM sennet/api-base-image:1.0.0
ENV LANG=en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

LABEL description="SenNet Ingest API RQ Service"

# Output right away
ENV PYTHONUNBUFFERED 1

WORKDIR /usr/src/app

# Copy from host to image
COPY .. .

RUN pip install --upgrade pip && \
    pip install -r ./src/requirements.txt && \
    pip install -r ./src/submodules/ingest_validation_tools/requirements.txt

CMD ["python", "src/worker.py"]
