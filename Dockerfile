FROM python:3.12.0a7-slim

RUN mkdir logzio
WORKDIR logzio
COPY requirements.txt .
COPY main.py .
COPY __init__.py .
COPY setup.py .
RUN pip install -r requirements.txt

# Get version from setup.py
RUN python setup.py --version > VERSION
ARG VERSION=$(cat VERSION)
ENV APP_VERSION=${VERSION}

ENTRYPOINT [ "python","./main.py"]
