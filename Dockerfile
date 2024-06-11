FROM python:3.12.0a7-slim

RUN mkdir logzio
WORKDIR logzio

COPY pyproject.toml .  
COPY setup.py . 

# Install the rest of the dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Get version from setup.py and store it in VERSION file
RUN python setup.py --version > VERSION

# Set environment variable for version
ARG VERSION=$(cat VERSION)
ENV APP_VERSION=${VERSION}

COPY main.py .
COPY __init__.py .

ENTRYPOINT ["python", "./main.py"]
