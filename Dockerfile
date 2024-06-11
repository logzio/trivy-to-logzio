FROM python:3.12.0a7-slim

# Install git
RUN apt-get update && apt-get install -y git

RUN mkdir logzio
WORKDIR logzio

COPY main.py .
COPY pyproject.toml ./
COPY setup.py ./

# Install necessary dependencies for setuptools_scm
RUN pip install setuptools setuptools_scm

# Install the rest of the dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the rest of the application files
COPY . .

# Set the version using setuptools_scm
RUN python -c "import setuptools_scm; print(setuptools_scm.get_version())" > VERSION

# Set environment variable for version
ARG VERSION=$(cat VERSION)
ENV APP_VERSION=${VERSION}

ENTRYPOINT ["python", "./main.py"]
