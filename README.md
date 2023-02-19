# Trivy to Logzio

This project allows sending [Trivy](https://github.com/aquasecurity/trivy-operator) vulnerability reports from your K8S cluster to Logz.io.  

## Prerequisites:

-[Trivy operator](https://github.com/aquasecurity/trivy-operator) running on your K8S cluster.

## Getting Started

### 1. Create monitoring namespace

Your CronJob will be deployed under the namespace `monitoring`. To create the namespace use:

```shell
kubectl create namespace monitoring
```

### 2. Store your Logz.io credentials

Save your Logz.io shipping credentials as a Kubernetes secret:

```shell
kubectl create secret generic logzio-logs-secret-trivy \
--from-literal=logzio-log-shipping-token='<<LOG-SHIPPING-TOKEN>>' \
--from-literal=logzio-log-listener='https://<<LISTENER-HOST>>:8071' \
-n monitoring
```

- Replace `<<LOG-SHIPPING-TOKEN>>` with the [token](https://app.logz.io/#/dashboard/settings/general) of the account you want to ship to. 
- Replace `<<LISTENER-HOST>>` with your region's listener host (for example, `listener.logz.io`). For more information on finding your account's region,
see [Account region](https://docs.logz.io/user-guide/accounts/account-region.html).

### 3. Download the cron job yaml

```shell
wget https://raw.githubusercontent.com/logzio/trivy-to-logzio/master/cronJob.yaml
```

In the cron job file, edit the following fields:

- `schedule` - the cron expression which schedules the cron job. For example - `"0 7 * * *"` will trigger the job to run everyday at 07:00 AM (cluster timezone).
- `ENV_ID value` - replace default value `my_env_id` with your env id.

### 4. Deploy your cron job

```shell
kubectl apply -f /path/to/your/file.yaml
```


#### 5.  Check Logz.io for your logs

Give your logs some time to get from your system to ours, and then open [Kibana](https://app.logz.io/#/dashboard/kibana).

If you still don't see your logs, see [log shipping troubleshooting](https://docs.logz.io/user-guide/log-shipping/log-shipping-troubleshooting.html).


## Changlog:

- **0.0.1** - Initial release.
