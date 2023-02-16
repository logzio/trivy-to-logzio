import json
import logging
import os
import time
import urllib
from kubernetes import client, config

ENV_LOGS_TOKEN = 'LOGZIO_LOG_SHIPPING_TOKEN'
ENV_LOGZIO_LISTENER = 'LOGZIO_LOG_LISTENER'
ENV_ENV_ID = 'ENV_ID'
LOGZIO_TOKEN = os.getenv(ENV_LOGS_TOKEN, '')
LOGZIO_LISTENER = os.getenv(ENV_LOGZIO_LISTENER, 'https://listener.logz.io:8071')
ENV_ID = os.getenv(ENV_ENV_ID, '')

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger()
config.load_incluster_config()
v1_client = client.CoreV1Api()

# todo: delete the following-
send_counter = 0


def run():
    if not is_valid_input():
        return
    namespaces = get_namespaces()
    for ns in namespaces:
        get_vulnerabilities(ns.metadata.name)


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


def get_vulnerabilities(ns):
    api_client = client.ApiClient()
    custom_api = client.CustomObjectsApi(api_client)
    logger.debug(f'in namespace: {ns}')
    crd_list = custom_api.list_namespaced_custom_object(group='aquasecurity.github.io', version='v1alpha1',
                                                        plural='vulnerabilityreports', namespace=ns)['items']
    for item in crd_list:
        process_item(item, ns)


def process_item(item, ns):
    try:
        if 'managedFields' in item['metadata']:
            del(item['metadata']['managedFields'])
        pods = get_related_pods(item, ns)
        for pod in pods:
            item['pod_name'] = pod
            send_to_logzio(item)
    except Exception as e:
        logger.debug(f'item: {item}')
        logger.warning(f'Error while processing item: {e}')


def get_related_pods(item, ns):
    # resource_type = get_resource_type(item)
    # logger.debug(f'resource type: {resource_type}')
    resource_name = get_resource_name(item)
    # logger.debug(f'resource name: {resource_name}')
    # # Todo - if resource type doesnt matter for querying - refactor here
    # if resource_type == 'daemonset':
    #     return get_ds_pods(resource_name, ns)
    # elif resource_type == 'replicaset':
    #     return get_ds_pods(resource_name, ns)
    selector = get_resource_selectors(item, resource_name)
    if selector == '':
        return []
    get_pod_names_by_selectors(selector, ns, resource_name)


def get_resource_selectors(item, resource_name):
    selector_strs = []
    selector = ''
    try:
        logging.info(item)
        for key in item['spec']['selector']['matchLabels']:
            selector_strs.append(f'{key}={item["spec"]["selector"]["matchLabels"][key]}')
        selector = ','.join(selector_strs)
    except Exception as e:
        logger.error(f'Error while trying to get selectors for {resource_name}: {e}')
    return selector


def get_pod_names_by_selectors(selector, ns, resource_name):
    names = []
    pods_list = v1_client.list_namespaced_pod(namespace=ns, label_selector=selector)
    for pod in pods_list.items:
        names.append(pod.metadata.name)
    logger.info(f'found {len(names)} related pods to resource {resource_name}')
    return names


def get_resource_name(item):
    if 'ownerReferences' in item['metadata'] and 'name' in item['metadata']['ownerReferences']:
        return item['metadata']['ownerReferences']['name'].lower()
    if 'labels' in item['metadata'] and 'trivy-operator.resource.name' in item['metadata']['labels']:
        return item['metadata']['labels']['trivy-operator.resource.name'].lower()


def get_resource_type(item):
    if 'ownerReferences' in item['metadata'] and 'kind' in item['metadata']['ownerReferences']:
        return item['metadata']['ownerReferences']['kind'].lower()
    if 'labels' in item['metadata'] and 'trivy-operator.resource.kind' in item['metadata']['labels']:
        return item['metadata']['labels']['trivy-operator.resource.kind'].lower()


def send_to_logzio(item):
    item['type'] = 'trivy_scan'
    data_body = json.dumps(item)
    request = urllib.request.Request(f'{LOGZIO_LISTENER}?token={LOGZIO_TOKEN}', data=str.encode(data_body),
                                     headers={'Content-type': 'application/json'})
    response = urllib.request.urlopen(request)
    global send_counter
    send_counter += 1


if __name__ == '__main__':
    logger.debug('started run')
    run()
    logger.info(f'sent {send_counter} logs')
    # todo - remove:
    time.sleep(600)
