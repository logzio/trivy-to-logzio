# Trivy to Logzio

This project allows sending [Trivy](https://github.com/aquasecurity/trivy-operator) vulnerability reports from your K8S cluster to Logz.io.  

To use it, see Logz.io's [logzio-trivy Helm Chart](https://github.com/logzio/logzio-helm/tree/master/charts/logzio-trivy).

**Note**: This project is in _beta_ and is subject to changes.

## Kubernetes versions compatibility

| Version | Kubernetes Version |
|---|---|
| >= 0.3.0 | v1.31.0 - v1.36.0 |


## Changelog:
- **0.3.0**:
  - Fix watch thread crashing on watch drop.
  - Fix error message when `ENV_ID` is missing, and exit on startup when `ENV_ID` or the shipping token is missing.
  - Recover the watch when its resource version expires (HTTP 410), instead of retrying with it forever.
  - Remove unused build dependencies (`git`, `setuptools_scm`) from the image.
  - Upgrade python version to 3.15.2.
  - Upgrade dependencies
    - `kubernetes` to `37.0.1`
    - `urllib3` to `2.8.0`
- **0.2.3**:
  - Upgrade python version to 3.12.5.
  - Re-build image to include the latest version of git(CVE-2024-32002).
- **0.2.2**:
  - Added 'user-agent' header for telemetry data.
- **0.2.1**:
  - Bump base docker image version.
  - Bump packages in requirements.
- **0.2.0**:
  - Watch events once the code starts running, along with a daily scheduled scan for reports.
- **0.1.0**:
  - **Breaking changes**:
    - Script will run always.
    - Scanning for reports will occur once upon script start, then once a day at the scheduled time. 
    - Not using Cron expressions anymore. Instead, set a time for the daily run in form of HH:MM.  
- **0.0.1** - Initial release.
