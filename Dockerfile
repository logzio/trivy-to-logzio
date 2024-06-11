FROM python:3.12.0a7-slim

RUN mkdir logzio
WORKDIR logzio
COPY requirements.txt .
COPY main.py .
COPY __init__.py .
COPY setup.py .
COPY pyproject.toml . 

RUN pip install -r requirements.txt

RUN python setup.py --version > VERSION

# Set environment variable for version
ARG VERSION=$(cat VERSION)
ENV APP_VERSION=${VERSION}

ENTRYPOINT ["python", "./main.py"]
