FROM python:3.12.0a7-slim

# Install git
RUN apt-get update && apt-get install -y git

RUN mkdir logzio
WORKDIR logzio

COPY main.py .
COPY pyproject.toml ./
COPY setup.py ./
COPY requirements.txt .

# Install build dependencies and other requirements
RUN pip install --upgrade pip setuptools>=61 setuptools_scm && pip install -r requirements.txt

# Copy the rest of the application files
COPY . .

# Set the version using setuptools_scm
RUN python -c "import setuptools_scm; print(setuptools_scm.get_version())" > VERSION

# Set environment variable for version
ARG VERSION=$(cat VERSION)
ENV APP_VERSION=${VERSION}

ENTRYPOINT ["python", "./main.py"]
