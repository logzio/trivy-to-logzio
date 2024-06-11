import json
import logging
import os
import time
import threading
from kubernetes import client, config, watch
import urllib3
import schedule
from importlib.metadata import version, PackageNotFoundError

ENV_LOGS_TOKEN = 'LOGZIO_LOG_SHIPPING_TOKEN'
ENV_LOGZIO_LISTENER = 'LOGZIO_LOG_LISTENER'
ENV_ENV_ID = 'ENV_ID'
ENV_LOG_LEVEL = 'LOG_LEVEL'
ENV_SCHEDULE = 'SCHEDULE'
LOGZIO_TOKEN = os.getenv(ENV_LOGS_TOKEN, '')
LOGZIO_LISTENER = os.getenv(ENV_LOGZIO_LISTENER, 'https://listener.logz.io:8071')
ENV_ID = os.getenv(ENV_ENV_ID, '')
RUN_SCHEDULE = os.getenv(ENV_SCHEDULE, '07:00')
# APP_VERSION = os.getenv('APP_VERSION', 'unknown')
GROUP = 'aquasecurity.github.io'
VERSION = 'v1alpha1'
CRDS = ['vulnerabilityreports']
try:
    APP_VERSION = version('your-package-name')  # Replace 'your-package-name' with the actual package name
except PackageNotFoundError:
    APP_VERSION = 'unknown'

def get_log_level():
    try:
        lvl = os.getenv(ENV_LOG_LEVEL, 'INFO').upper()
        return logging.getLevelName(lvl)
    except Exception as e:
        return logging.INFO


logging.basicConfig(format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s', level=get_log_level())
logger = logging.getLogger()
config.load_incluster_config()


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
                num_vulnerabilities = len(item['report']['vulnerabilities'])
                num_pools = num_vulnerabilities if num_vulnerabilities > 0 else 1
                http = urllib3.PoolManager(num_pools=num_pools)
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
    try_num = 1
    data_body = json.dumps(log)
    data_body_bytes = str.encode(data_body)
    url = f'{LOGZIO_LISTENER}?token={LOGZIO_TOKEN}'
    headers = {
        'Content-type': 'application/json',
        'user-agent': f'logzio-trivy-version-{APP_VERSION}-logs-test'
    }
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
            logger.warning(f'try {try_num}/{max_retries} failed')
            logger.warning(f'Status code: {r.status}')
            logger.warning(f'Response body: {r.read()}')
            try_num += 1
        except Exception as e:
            logger.warning(f'Try {try_num}/{max_retries} failed: {e}')
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


def run_triggered(crd_object):
    logger.info(f'Start processing security scan')
    logger.debug(crd_object)
    process_item(crd_object)
    logger.info(f'Done processing security scan')


def watch_crd(custom_resource_name):
    api_client = client.ApiClient()
    custom_api = client.CustomObjectsApi(api_client)
    watched_uids = list()
    resource_version = 0
    while True:
        try:
            w = watch.Watch()
            logger.info('Watching for new reportss...')
            logger.debug(f'Latest resource version: {resource_version}')
            if resource_version > 0:
                for event in w.stream(custom_api.list_namespaced_custom_object,
                                      GROUP, VERSION, '', custom_resource_name, watch=True, timeout_seconds=240, resource_version=resource_version):
                    resource_version = process_event(event, watched_uids, resource_version)
            else:
                for event in w.stream(custom_api.list_namespaced_custom_object,
                                      GROUP, VERSION, '', custom_resource_name, watch=True, timeout_seconds=240):
                    resource_version = process_event(event, watched_uids, resource_version)
            logger.debug(f'Watch timed-out')
            w.stop()
            logger.debug(f'running: {threading.enumerate()}')
            logger.debug('Restarting watch in 5 seconds')
            time.sleep(5)
        except exceptions.ProtocolError as pe:
            logger.info(f'Received: {pe}')
            logger.info('Will close and reopen watch in 5 seconds')
            w.stop()
            time.sleep(5)
            continue
        except Exception as e:
            logger.warning(f'Error while watching for new {custom_resource_name}: {e}, will retry watch')
            w.stop()
            time.sleep(5)
            continue


def process_event(event, watched_uids, recent_version):
    curr_uid = event['object']['metadata']['uid']
    event_type = event['type'].lower()
    resource_name = event['object']['metadata']['labels']['trivy-operator.container.name']
    if (curr_uid in watched_uids and event_type == 'added') or \
            (curr_uid not in watched_uids and event_type == 'deleted'):
        logger.debug(f'Event {event_type} for CRD uid {curr_uid} will be ignored')
        return recent_version
    if curr_uid in watched_uids and event_type == 'deleted':
        logger.debug(f'CRD with uid {curr_uid} deleted, removing uid from watched list')
        watched_uids.remove(curr_uid)
        return recent_version
    if curr_uid not in watched_uids:
        logger.debug(f'New CRD to watch: {curr_uid}')
        watched_uids.append(curr_uid)
    if event_type == 'modified':
        logger.info(f'Detected changes in security scan for {resource_name}')
    t_trigger = threading.Thread(target=run_triggered, args=(event['object'],), name=f'watch_{resource_name}')
    t_trigger.start()
    current_version = int(event['object']['metadata']['resourceVersion'])
    latest_version = current_version if current_version > recent_version else recent_version
    return latest_version


if __name__ == '__main__':
    logger.info('Starting Trivy-to-Logzio')

    # scheduled run
    schedule.every().day.at(RUN_SCHEDULE).do(run_logic)
    t_scheduled = run_continuously()

    # event triggered run
    logger.info('Starting to watch events... ')
    threads_watch = []
    for crd in CRDS:
        t_crd = threading.Thread(target=watch_crd, args=(crd,), name=f'watch_{crd}')
        threads_watch.append(t_crd)
        t_crd.start()
    for t in threads_watch:
        t.join()
    logger.error('Unexpectedly stopped watching. Exiting.')
