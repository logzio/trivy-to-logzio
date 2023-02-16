import json
import logging
import os
import time
from kubernetes import client, config
import urllib3

ENV_LOGS_TOKEN = 'LOGZIO_LOG_SHIPPING_TOKEN'
ENV_LOGZIO_LISTENER = 'LOGZIO_LOG_LISTENER'
ENV_ENV_ID = 'ENV_ID'
LOGZIO_TOKEN = os.getenv(ENV_LOGS_TOKEN, '')
LOGZIO_LISTENER = os.getenv(ENV_LOGZIO_LISTENER, 'https://listener.logz.io:8071')
ENV_ID = os.getenv(ENV_ENV_ID, '')

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger()
config.load_incluster_config()
api_client = client.ApiClient()
v1_client = client.CoreV1Api()
api_instance = client.AppsV1Api(api_client)
http = urllib3.PoolManager()

# todo: delete the following-
send_counter = 0


def run():
    if not is_valid_input():
        return
    namespaces = get_namespaces()
    for ns in namespaces:
        get_reports(ns.metadata.name)


def is_valid_input():
    if LOGZIO_TOKEN == '':
        logger.error(f'{ENV_LOGS_TOKEN} not supplied. Exiting.')
        return False
    if ENV_ID == '':
        logger.error(f'{ENV_LOGS_TOKEN} not supplied. Exiting.')
        return False
    return True


def get_namespaces():
    return v1_client.list_namespace().items


def get_reports(ns):
    custom_api = client.CustomObjectsApi(api_client)
    crds = ['vulnerabilityreports']
    for crd in crds:
        crd_list = custom_api.list_namespaced_custom_object(group='aquasecurity.github.io', version='v1alpha1',
                                                            plural=crd, namespace=ns)['items']
        logger.info(f'found {len(crd_list)} reports in namespace {ns}')
        for item in crd_list:
            process_item(item, ns)


def process_item(item):
    try:
        metadata = get_report_metadata(item)
        if metadata is not None:
            for vulnerability in item['report']['vulnerabilities']:
                create_and_send_log(vulnerability, metadata)
    except Exception as e:
        logger.debug(f'Item: {item}')
        logger.warning(f'Error while processing item: {e}')


def create_and_send_log(vulnerability, metadata):
    log = dict()
    log.update(metadata)
    log.update(vulnerability)
    # logzio parameters:
    log['type'] = 'trivy_scan'
    log['env_id'] = ENV_ID
    send_to_logzio(log)


def get_report_metadata(item):
    try:
        metadata = dict()
        metadata['metadata'] = {'annotations': {'trivy-operator.aquasecurity.github.io/report-ttl': item['metadata']['annotations']['trivy-operator.aquasecurity.github.io/report-ttl']},
                                'creationTimestamp': item['metadata']['creationTimestamp'],
                                'generation': item['metadata']['generation'],
                                'name': item['metadata']['name']}
        metadata['kubernetes'] = {'pod_name': item['metadata']['labels']['trivy-operator.resource.name'],
                                  'namespace_name': item['metadata']['labels']['trivy-operator.resource.namespace'],
                                  'container_name': item['metadata']['labels']['trivy-operator.container.name'],
                                  'resource_kind': item['metadata']['labels']['trivy-operator.resource.kind']}
        metadata['report'] = {'artifact': {'repository': item['report']['artifact']['repository'], 'tag': item['report']['artifact']['tag']},
                              'registry': item['report']['registry'],
                              'scanner': item['report']['scanner']}
        return metadata
    except Exception as e:
        logger.error(f'Error while getting metadata from item: {e}')
        return None


def send_to_logzio(log):
    max_retries = 5
    try_num = 0
    data_body = json.dumps(log)
    data_body_bytes = str.encode(data_body)
    url = f'{LOGZIO_LISTENER}?token={LOGZIO_TOKEN}'
    headers = {'Content-type': 'application/json'}
    global send_counter
    while try_num <= max_retries:
        try:
            time.sleep(try_num * 2)
            r = http.request(method='POST', url=url, headers=headers, body=data_body_bytes)
            if r.status == 200:
                send_counter += 1
                logger.debug(f'Successfully sent log {log} to logzio')
                return
            elif r.status == 400:
                logger.error(f'Malformed log: {log} will not be send')
                return
            elif r.status == 401:
                logger.error(f'Invalid token, cannot send to logzio')
                return
            logger.warning(f'try {try_num + 1}/{max_retries} failed')
            logger.warning(f'Status code: {r.status}')
            logger.warning(f'Response body: {r.read()}')
            try_num += 1
        except Exception as e:
            logger.warning(f'Try {try_num + 1}/{max_retries} failed: {e}')
            try_num += 1


if __name__ == '__main__':
    logger.info('Started run')
    run()
    logger.info(f'Sent {send_counter} logs')
    logger.info('Finished run')
    # todo - remove:
    time.sleep(600)
