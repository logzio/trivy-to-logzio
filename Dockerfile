FROM python:3.15.2-slim

RUN mkdir logzio
WORKDIR logzio

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Set by CI from the release tag
ARG VERSION=unknown
ENV APP_VERSION=${VERSION}

ENTRYPOINT ["python", "./main.py"]