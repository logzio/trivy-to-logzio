FROM python:3.11

RUN mkdir logzio
WORKDIR logzio
COPY requirements.txt .
COPY main.py .
COPY __init__.py .
RUN pip install -r requirements.txt

ENTRYPOINT [ "python","./main.py"]


