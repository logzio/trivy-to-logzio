import json
import logging
import os
import time
import threading
from kubernetes import client, config, watch
import urllib3
import schedule

ENV_LOGS_TOKEN = 'LOGZIO_LOG_SHIPPING_TOKEN'
ENV_LOGZIO_LISTENER = 'LOGZIO_LOG_LISTENER'
ENV_ENV_ID = 'ENV_ID'
ENV_LOG_LEVEL = 'LOG_LEVEL'
ENV_SCHEDULE = 'SCHEDULE'
LOGZIO_TOKEN = os.getenv(ENV_LOGS_TOKEN, '')
LOGZIO_LISTENER = os.getenv(ENV_LOGZIO_LISTENER, 'https://listener.logz.io:8071')
ENV_ID = os.getenv(ENV_ENV_ID, '')
RUN_SCHEDULE = os.getenv(ENV_SCHEDULE, '07:00')
GROUP = 'aquasecurity.github.io'
VERSION = 'v1alpha1'
CRDS = ['vulnerabilityreports']


def get_log_level():
    try:
        lvl = os.getenv(ENV_LOG_LEVEL, 'INFO').upper()
        return logging.getLevelName(lvl)
    except Exception as e:
        return logging.INFO


logging.basicConfig(format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s', level=get_log_level())
logger = logging.getLogger()
config.load_incluster_config()
# api_client = client.ApiClient()
# api_instance = client.AppsV1Api(api_client)
# custom_api = client.CustomObjectsApi(api_client)
# http = urllib3.PoolManager(num_pools=10)


def run_logic():
    if not is_valid_input():
        return
    get_reports()
    logger.info('Done processing')


def is_valid_input():
    if LOGZIO_TOKEN == '':
        logger.error(f'{ENV_LOGS_TOKEN} not supplied. Exiting.')
        return False
    if ENV_ID == '':
        logger.error(f'{ENV_LOGS_TOKEN} not supplied. Exiting.')
        return False
    return True


# def get_namespaces():
#     return v1_client.list_namespace().items


def get_reports():
    api_client = client.ApiClient()
    custom_api = client.CustomObjectsApi(api_client)
    for crd in CRDS:
        crd_list = custom_api.list_namespaced_custom_object(group=GROUP, version=VERSION,
                                                            plural=crd, namespace='')['items']
        logger.info(f'found {len(crd_list)} reports')
        for item in crd_list:
            process_item(item)


def process_item(item):
    try:
        metadata = get_report_metadata(item)
        related_pods = get_pods_data(metadata['kubernetes'])
        if metadata is not None:
            for pod_data in related_pods:
                http = urllib3.PoolManager(num_pools=len(item['report']['vulnerabilities']))
                for vulnerability in item['report']['vulnerabilities']:
                    create_and_send_log(metadata, pod_data, http, vulnerability)
                if len(item['report']['vulnerabilities']) == 0:
                    logger.debug(f'No vulnerabilities for {metadata["kubernetes"]["resource_kind"]}/{metadata["kubernetes"]["resource_name"]}')
                    create_and_send_log(metadata, pod_data, http)
    except Exception as e:
        logger.debug(f'Item: {item}')
        logger.warning(f'Error while processing item: {e}')


def create_and_send_log(metadata, pod_data, http_client, vulnerability=None):
    log = dict()
    log.update(metadata)
    log['kubernetes'].update(pod_data)
    log.update(get_logzio_fields())
    if vulnerability is not None:
        log.update(vulnerability)
    else:
        log['message'] = 'No vulnerabilities for this pod at the moment.'
    send_to_logzio(log, http_client)


def get_logzio_fields():
    return {'type': 'trivy_scan',
            'env_id': ENV_ID}


def get_report_metadata(item):
    try:
        metadata = dict()
        metadata['metadata'] = {'annotations': {
            'trivy-operator.aquasecurity.github.io/report-ttl': item['metadata']['annotations'][
                'trivy-operator.aquasecurity.github.io/report-ttl']},
                                'creationTimestamp': item['metadata']['creationTimestamp'],
                                'generation': item['metadata']['generation'],
                                'name': item['metadata']['name']}
        metadata['kubernetes'] = {'resource_name': item['metadata']['labels']['trivy-operator.resource.name'],
                                  'namespace_name': item['metadata']['labels']['trivy-operator.resource.namespace'],
                                  'container_name': item['metadata']['labels']['trivy-operator.container.name'],
                                  'resource_kind': item['metadata']['labels']['trivy-operator.resource.kind']}
        metadata['report'] = {'artifact': {'repository': item['report']['artifact']['repository'],
                                           'tag': item['report']['artifact']['tag']},
                              'registry': item['report']['registry'],
                              'scanner': item['report']['scanner']}
        return metadata
    except Exception as e:
        logger.error(f'Error while getting metadata from item: {e}')
        return None


def get_pods_data(resource_data):
    try:
        api_client = client.ApiClient()
        api_instance = client.AppsV1Api(api_client)
        v1_client = client.CoreV1Api()
        ns_pods = v1_client.list_namespaced_pod(namespace=resource_data['namespace_name'])
        related_pods = []
        for ns_pod in ns_pods.items:
            if ns_pod.metadata.owner_references[0].name == resource_data['resource_name']:
                pod_data = {'pod_name': ns_pod.metadata.name,
                            'pod_ip': ns_pod.status.pod_ip,
                            'host_ip': ns_pod.status.host_ip,
                            'node_name': ns_pod.spec.node_name,
                            'pod_uid': ns_pod.metadata.uid}
                if resource_data['resource_kind'].lower() == 'replicaset':
                    try:
                        rs_data = api_instance.read_namespaced_replica_set(name=resource_data['resource_name'], namespace=resource_data['namespace_name'])
                        if rs_data.metadata.owner_references[0].kind.lower() == 'deployment':
                            pod_data['deployment_name'] = rs_data.metadata.owner_references[0].name
                    except Exception as e:
                        logger.error(f'Error while trying to get deployment of replicaset: {e}')
                related_pods.append(pod_data)
        logger.debug(
            f'Related pods for {resource_data["resource_kind"]}/{resource_data["resource_name"]} in ns {resource_data["namespace_name"]}: {related_pods}')
        if len(related_pods) == 0:
            logger.info(
                f'No available pods running matching report for {resource_data["resource_kind"]}/{resource_data["resource_name"]} in ns {resource_data["namespace_name"]}, will not be sent')
        return related_pods
    except Exception as e:
        logger.error(
            f'Error while extracting host info for {resource_data["resource_kind"]}/{resource_data["resource_name"]} from namespace {resource_data["namespace_name"]}: {e}')
        return {}


def send_to_logzio(log, http_client):
    max_retries = 5
    try_num = 0
    data_body = json.dumps(log)
    data_body_bytes = str.encode(data_body)
    url = f'{LOGZIO_LISTENER}?token={LOGZIO_TOKEN}'
    headers = {'Content-type': 'application/json'}
    while try_num <= max_retries:
        try:
            time.sleep(try_num * 2)
            r = http_client.request(method='POST', url=url, headers=headers, body=data_body_bytes)
            if r.status == 200:
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


def run_continuously(interval=1):
    """Continuously run, while executing pending jobs at each
    elapsed time interval.
    """
    logger.info('Starting scheduled thread...')
    cease_continuous_run = threading.Event()

    class ScheduleThread(threading.Thread):
        @classmethod
        def run(cls):
            while not cease_continuous_run.is_set():
                schedule.run_pending()
                time.sleep(interval)

    continuous_thread = ScheduleThread(name='scheduled')
    continuous_thread.start()
    logger.info(f'Scheduled thread is set to run everyday at: {RUN_SCHEDULE} (cluster time)')
    return continuous_thread


# def get_current_resources():
#     resources = v1_client.list_pod_for_all_namespaces(watch=False)
#     owner_names = []
#     for resource in resources.items:
#         name = resource.metadata.owner_references[0].name
#         if name not in owner_names:
#             owner_names.append(name)
#     return owner_names


# def wait_for_trivy_scan():
#     timeout = 5
#     scans = 0
#     logger.info('Waiting for Trivy scan to create reports. This may take a few minutes...')
#     resources = get_current_resources()
#     while scans < len(resources):
#         crd_list = custom_api.list_namespaced_custom_object(group=GROUP, version=VERSION,
#                                                             plural='vulnerabilityreports', namespace='')['items']
#         scans = len(crd_list)
#         logger.debug(f'Currently found {scans} scans, and there are at least {len(resources)} resources on the cluster')
#         if scans < len(resources):
#             logger.debug(f'Waiting for trivy...')
#             time.sleep(timeout)
#     logger.info('Done waiting for Trivy scans')


def run_triggered(crd_object):
    logger.info('Detected new security scan')
    logger.debug(crd_object)
    process_item(crd_object)
    logger.info('Done processing new security scan')


def watch_crd(custom_resource_name):
    api_client = client.ApiClient()
    custom_api = client.CustomObjectsApi(api_client)
    while True:
        try:
            for event in w.stream(custom_api.list_namespaced_custom_object,
                                  GROUP, VERSION, '', custom_resource_name, watch=True):
                if event['type'].lower() == 'added':
                    t_trigger = threading.Thread(target=run_triggered, args=(event['object'],))
                    t_trigger.start()

        except Exception as e:
            logger.error(f'Error while watching for new {custom_resource_name}: {e}')


if __name__ == '__main__':
    logger.info('Starting Trivy-to-Logzio')

    # scheduled run
    schedule.every().day.at(RUN_SCHEDULE).do(run_logic)
    t_scheduled = run_continuously()

    # wait for trivy to scan
    # t_scan = threading.Thread(target=wait_for_trivy_scan, name='wait-for-scan')
    # t_scan.start()
    # t_scan.join()

    # first run upon deployment
    # t_first = threading.Thread(target=run_logic, name='first-run')
    # t_first.start()
    # t_first.join()

    # waiting for the scheduled thread to finish prevents the script from exiting
    # t_scheduled.join()

    # event triggered run
    logger.info('Starting to watch events... ')
    w = watch.Watch()
    threads_watch = []
    for crd in CRDS:
        t_crd = threading.Thread(target=watch_crd, args=(crd,), name=f'watch_{crd}')
        threads_watch.append(t_crd)
        t_crd.start()
        # try:
        #     for event in w.stream(custom_api.list_namespaced_custom_object,
        #                           GROUP, VERSION, '', crd, watch=True):
        #         if event['type'].lower() == 'added':
        #             t_trigger = threading.Thread(target=run_triggered, args=(event['object'],))
        #             t_trigger.start()
        # except Exception as e:
        #     logger.error(f'Error while watching for new {crd}: {e}')
    for t in threads_watch:
        t.join()
    logger.error('Unexpectedly stopped watching. Exiting.')



