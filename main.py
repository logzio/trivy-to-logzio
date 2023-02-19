import json
import logging
import os
import time
from kubernetes import client, config
import urllib3

ENV_LOGS_TOKEN = 'LOGZIO_LOG_SHIPPING_TOKEN'
ENV_LOGZIO_LISTENER = 'LOGZIO_LOG_LISTENER'
ENV_ENV_ID = 'ENV_ID'
ENV_LOG_LEVEL = 'LOG_LEVEL'
LOGZIO_TOKEN = os.getenv(ENV_LOGS_TOKEN, '')
LOGZIO_LISTENER = os.getenv(ENV_LOGZIO_LISTENER, 'https://listener.logz.io:8071')
ENV_ID = os.getenv(ENV_ENV_ID, '')


def get_log_level():
    try:
        lvl = os.getenv(ENV_LOG_LEVEL, 'INFO').upper()
        return logging.getLevelName(lvl)
    except Exception as e:
        return logging.INFO


logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=get_log_level())
logger = logging.getLogger()
config.load_incluster_config()
api_client = client.ApiClient()
v1_client = client.CoreV1Api()
api_instance = client.AppsV1Api(api_client)
http = urllib3.PoolManager()

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
            process_item(item)


def process_item(item):
    try:
        metadata = get_report_metadata(item)
        related_pods = get_pods_data(metadata['kubernetes'])
        if metadata is not None:
            for pod_data in related_pods:
                for vulnerability in item['report']['vulnerabilities']:
                    create_and_send_log(vulnerability, metadata, pod_data)
    except Exception as e:
        logger.debug(f'Item: {item}')
        logger.warning(f'Error while processing item: {e}')


def create_and_send_log(vulnerability, metadata, pod_data):
    log = dict()
    log.update(metadata)
    log.update(vulnerability)
    log['kubernetes'].update(pod_data)
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
        metadata['kubernetes'] = {'resource_name': item['metadata']['labels']['trivy-operator.resource.name'],
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


def get_pods_data(resource_data):
    try:
        ns_pods = v1_client.list_namespaced_pod(namespace=resource_data['namespace_name'])
        related_pods = []
        for ns_pod in ns_pods.items:
            if ns_pod.metadata.owner_references[0].name == resource_data['resource_name']:
                pod_data = {'pod_name': ns_pod.metadata.name,
                            'pod_ip': ns_pod.status.pod_ip,
                            'host_ip': ns_pod.status.host_ip,
                            'node_name': ns_pod.spec.node_name}
                related_pods.append(pod_data)
        logger.debug(f'Related pods for {resource_data["resource_kind"]}/{resource_data["resource_name"]} in ns {resource_data["namespace_name"]}: {related_pods}')
        if len(related_pods) == 0:
            logger.error(f'Could not find pods matching the details, report for {resource_data["resource_kind"]}/{resource_data["resource_name"]} in ns {resource_data["namespace_name"]} will not be send')
        return related_pods
    except Exception as e:
        logger.error(f'Error while extracting host info for {resource_data["resource_kind"]}/{resource_data["resource_name"]} from namespace {ns}: {e}')
        return {}


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
