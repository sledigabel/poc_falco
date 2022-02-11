# poc_falco
This repository is containing a proof of concept on falco for k8s

## Setup

First, setup minikube
```bash
minikube start --profile falco --driver hyperkit --cpus 4 --memory 8GiB
```

Get the helm chart from this [link](https://github.com/falcosecurity/charts/tree/master/falco).

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

Then install the chart:

```bash
helm install falco falcosecurity/falco
```

Immediately we see a notice for falco to start (it detects itself as a privileged container):
```console
* Setting up /usr/src links from host
* Running falco-driver-loader for: falco version=0.31.0, driver version=319368f1ad778691164d33d59945e00c5752cd27
* Running falco-driver-loader with: driver=module, compile=yes, download=yes
* Unloading falco module, if present
* Looking for a falco module locally (kernel 4.19.202)
* Trying to download a prebuilt falco module from https://download.falco.org/driver/319368f1ad778691164d33d59945e00c5752cd27/falco_buildroot_4.19.202_1.ko
curl: (22) The requested URL returned error: 404
Unable to find a prebuilt falco module
* Trying to dkms install falco module with GCC /usr/bin/gcc
DIRECTIVE: MAKE="'/tmp/falco-dkms-make'"
* Running dkms build failed, couldn't find /var/lib/dkms/falco/319368f1ad778691164d33d59945e00c5752cd27/build/make.log (with GCC /usr/bin/gcc)
* Trying to dkms install falco module with GCC /usr/bin/gcc-8
DIRECTIVE: MAKE="'/tmp/falco-dkms-make'"
* Running dkms build failed, couldn't find /var/lib/dkms/falco/319368f1ad778691164d33d59945e00c5752cd27/build/make.log (with GCC /usr/bin/gcc-8)
* Trying to dkms install falco module with GCC /usr/bin/gcc-6
DIRECTIVE: MAKE="'/tmp/falco-dkms-make'"
* Running dkms build failed, couldn't find /var/lib/dkms/falco/319368f1ad778691164d33d59945e00c5752cd27/build/make.log (with GCC /usr/bin/gcc-6)
* Trying to dkms install falco module with GCC /usr/bin/gcc-5
DIRECTIVE: MAKE="'/tmp/falco-dkms-make'"
* Running dkms build failed, couldn't find /var/lib/dkms/falco/319368f1ad778691164d33d59945e00c5752cd27/build/make.log (with GCC /usr/bin/gcc-5)
* Trying to load a system falco module, if present
* Success: falco module found and loaded with modprobe
Fri Feb 11 09:28:24 2022: Falco version 0.31.0 (driver version 319368f1ad778691164d33d59945e00c5752cd27)
Fri Feb 11 09:28:24 2022: Falco initialized with configuration file /etc/falco/falco.yaml
Fri Feb 11 09:28:24 2022: Loading rules from file /etc/falco/falco_rules.yaml:
Fri Feb 11 09:28:25 2022: Loading rules from file /etc/falco/falco_rules.local.yaml:
Fri Feb 11 09:28:25 2022: Starting internal webserver, listening on port 8765
09:28:25.845349000: Notice Privileged container started (user=sys user_loginuid=0 command=container:b2dc3b248703 k8s.ns=kube-system k8s.pod=kube-proxy-v2ffs container=b2dc3b248703 image=k8s.gcr.io/pause:3.6) k8s.ns=kube-system k8s.pod=kube-proxy-v2ffs container=b2dc3b248703
09:28:25.881879000: Notice Privileged container started (user=root user_loginuid=0 command=container:a71aa02a7451 k8s.ns=default k8s.pod=falco-r5bkq container=a71aa02a7451 image=k8s.gcr.io/pause:3.6) k8s.ns=default k8s.pod=falco-r5bkq container=a71aa02a7451
```

I tried to create a dummy file in `/etc` as root and launch a privileged container:

```console
09:33:25.070639963: Error File below /etc opened for writing (user=root user_loginuid=-1 command=touch seb parent=bash pcmdline=bash file=/etc/seb program=touch gparent=bash ggparent=sshd gggparent=sshd container_id=host image=<NA>) k8s.ns=<NA> k8s.pod=<NA> container=host k8s.ns=<NA> k8s.pod=<NA> container=host
09:34:37.246663696: Notice Privileged container started (user=root user_loginuid=0 command=container:fae0c46cf3ce k8s.ns=<NA> k8s.pod=<NA> container=fae0c46cf3ce image=alpine:latest) k8s.ns=<NA> k8s.pod=<NA> container=fae0c46cf3ce
09:34:37.256482135: Notice Privileged container started (user=root user_loginuid=-1 command=sh k8s.ns=<NA> k8s.pod=<NA> container=fae0c46cf3ce image=alpine:latest) k8s.ns=<NA> k8s.pod=<NA> container=fae0c46cf3ce
```

## Fiddling

### JSON output

The output can be JSON
```yaml
---
falco:
  timeFormatISO8601: true
  jsonOutput: true
```

When deploying, we got:

```json
{
    "output": "2022-02-11T15:16:03.310607000+0000: Notice Privileged container started (user=root user_loginuid=0 command=container:8fbf0a6486b6 k8s.ns=default k8s.pod=falco-lrfjl container=8fbf0a6486b6 image=k8s.gcr.io/pause:3.6) k8s.ns=default k8s.pod=falco-lrfjl container=8fbf0a6486b6",
    "priority": "Notice",
    "rule": "Launch Privileged Container",
    "source": "syscall",
    "tags": [
        "cis",
        "container",
        "mitre_lateral_movement",
        "mitre_privilege_escalation"
    ],
    "time": "2022-02-11T15:16:03.310607000Z",
    "output_fields": {
        "container.id": "8fbf0a6486b6",
        "container.image.repository": "k8s.gcr.io/pause",
        "container.image.tag": "3.6",
        "evt.time.iso8601": 1644592563310607000,
        "k8s.ns.name": "default",
        "k8s.pod.name": "falco-lrfjl",
        "proc.cmdline": "container:8fbf0a6486b6",
        "user.loginuid": 0,
        "user.name": "root"
    }
}
```
