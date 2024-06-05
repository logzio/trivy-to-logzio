FROM python:3.12.0a7-slim

RUN mkdir logzio
WORKDIR logzio
COPY requirements.txt .
COPY main.py .
COPY __init__.py .
RUN pip install -r requirements.txt

# Set environment variable for version
ARG VERSION
ENV APP_VERSION=${VERSION}

ENTRYPOINT [ "python","./main.py"]


