# stash-redis

[stash-redis](https://github.com/stashed/redis) - Redis database backup/restore plugin for [Stash by AppsCode](https://stash.run)

## TL;DR;

```console
$ helm repo add appscode https://charts.appscode.com/stable/
$ helm repo update
$ helm install stash-redis-v2020.09.16 appscode/stash-redis -n kube-system --version=v2020.09.16
```

## Introduction

This chart deploys necessary `Function` and `Task` definition to backup or restore Redis 5.0.3 using Stash on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

## Prerequisites

- Kubernetes 1.11+

## Installing the Chart

To install the chart with the release name `stash-redis-v2020.09.16`:

```console
$ helm install stash-redis-v2020.09.16 appscode/stash-redis -n kube-system --version=v2020.09.16
```

The command deploys necessary `Function` and `Task` definition to backup or restore Redis 5.0.3 using Stash on the Kubernetes cluster in the default configuration. The [configuration](#configuration) section lists the parameters that can be configured during installation.

> **Tip**: List all releases using `helm list`

## Uninstalling the Chart

To uninstall/delete the `stash-redis-v2020.09.16`:

```console
$ helm delete stash-redis-v2020.09.16 -n kube-system
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Configuration

The following table lists the configurable parameters of the `stash-redis` chart and their default values.

|    Parameter     |                                                         Description                                                         |       Default       |
|------------------|-----------------------------------------------------------------------------------------------------------------------------|---------------------|
| nameOverride     | Overrides name template                                                                                                     | `""`                |
| fullnameOverride | Overrides fullname template                                                                                                 | `""`                |
| image.registry   | Docker registry used to pull Redis addon image                                                                              | `stashed`           |
| image.repository | Docker image used to backup/restore Redis database                                                                          | `stash-redis`       |
| image.tag        | Tag of the image that is used to backup/restore Redis database. This is usually same as the database version it can backup. | `v2020.09.16`       |
| backup.args      | Arguments to pass to `redisdump` command  during bakcup process                                                             | `"--all-databases"` |
| restore.args     | Arguments to pass to `redis` command during restore process                                                                 | `""`                |
| waitTimeout      | Number of seconds to wait for the database to be ready before backup/restore process.                                       | `300`               |


Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`. For example:

```console
$ helm install stash-redis-v2020.09.16 appscode/stash-redis -n kube-system --version=v2020.09.16 --set image.registry=stashed
```

Alternatively, a YAML file that specifies the values for the parameters can be provided while
installing the chart. For example:

```console
$ helm install stash-redis-v2020.09.16 appscode/stash-redis -n kube-system --version=v2020.09.16 --values values.yaml
```
