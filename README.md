
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

We see a notice for falco to start (it detects itself as a privileged container):

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

```yaml
{
    "output": "2022-02-11T15:22:50.024471562+0000: Notice A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=default k8s.pod=falco-lrfjl container=8b42665ac049 shell=sh parent=runc cmdline=sh terminal=34816 container_id=8b42665ac049 image=falcosecurity/falco) k8s.ns=default k8s.pod=falco-lrfjl container=8b42665ac049",
    "priority": "Notice",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": [
        "container",
        "mitre_execution",
        "shell"
    ],
    "time": "2022-02-11T15:22:50.024471562Z",
    "output_fields": {
        "container.id": "8b42665ac049",
        "container.image.repository": "falcosecurity/falco",
        "evt.time.iso8601": 1644592970024471562,
        "k8s.ns.name": "default",
        "k8s.pod.name": "falco-lrfjl",
        "proc.cmdline": "sh",
        "proc.name": "sh",
        "proc.pname": "runc",
        "proc.tty": 34816,
        "user.loginuid": -1,
        "user.name": "root"
    }
}
```

### Adding k8s logs

Falco can also read up the k8s logs as they come and derive alerts from it based on the same querying language.
For this to work, we need k8s to post logs as a webhook as they come into the falco pod. We need to enable the webserver to receive those webhooks.

[k8s audit logs for falco](https://github.com/falcosecurity/charts/tree/master/falco#enabling-k8s-audit-event-support)
[EKS Cloudwatch](https://github.com/sysdiglabs/ekscloudwatch)
[EKS logs into falco blog](https://faun.pub/analyze-aws-eks-audit-logs-with-falco-95202167f2e)

#### On Minikube

Following the [Guide](https://github.com/falcosecurity/evolution/tree/master/examples/k8s_audit_config#instructions-for-kubernetes-113) is failing.
That is because DynamicAuditing is deprecated since 1.19.

References:
- [FeatureGates](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/)
- Kube 1.19 [release notes](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.19.md)
- The [dynamic audit PR](https://github.com/kubernetes/kubernetes/pull/91502)

The idea is to configure the api server with a webhook statically.

```bash
minikube start --cpus 4 --memory 8GiB
helm install falco --values values.yaml falcosecurity/falco
git clone git@github.com:falcosecurity/evolution.git
pushd ./evolution/examples/k8s_audit_config
FALCO_SERVICE_CLUSTERIP=$(kubectl get service falco -o=jsonpath={.spec.clusterIP}) envsubst < webhook-config.yaml.in > webhook-config.yaml
bash enable-k8s-audit.sh minikube static
popd
```

This will reconfigure the api server on minikube, and it will take a while to restart.
The api-server's logs are reporting how many webhooks it has sent.

```console
{"log":"Trace[628419535]: [1.052845699s] [1.052845699s] END\n","stream":"stderr","time":"2022-02-15T13:59:42.411888879Z"}
{"log":"I0215 13:59:44.329471       1 trace.go:205] Trace[787090352]: \"Call Audit Events webhook\" name:webhook,event-count:12 (15-Feb-2022 13:59:43.301) (total time: 1027ms):\n","stream":"stderr","time":"2022-02-15T13:59:44.32976007Z"}
{"log":"Trace[787090352]: [1.027556675s] [1.027556675s] END\n","stream":"stderr","time":"2022-02-15T13:59:44.329791793Z"}
{"log":"I0215 13:59:44.521736       1 trace.go:205] Trace[1925773888]: \"Call Audit Events webhook\" name:webhook,event-count:13 (15-Feb-2022 13:59:43.497) (total time: 1024ms):\n","stream":"stderr","time":"2022-02-15T13:59:44.522390011Z"}
{"log":"Trace[1925773888]: [1.024471619s] [1.024471619s] END\n","stream":"stderr","time":"2022-02-15T13:59:44.522435607Z"}
{"log":"I0215 13:59:44.777424       1 trace.go:205] Trace[770366437]: \"Call Audit Events webhook\" name:webhook,event-count:7 (15-Feb-2022 13:59:43.731) (total time: 1046ms):\n","stream":"stderr","time":"2022-02-15T13:59:44.778251891Z"}
{"log":"Trace[770366437]: [1.046283543s] [1.046283543s] END\n","stream":"stderr","time":"2022-02-15T13:59:44.778291065Z"}
{"log":"I0215 13:59:44.777786       1 trace.go:205] Trace[214580956]: \"Call Audit Events webhook\" name:webhook,event-count:8 (15-Feb-2022 13:59:43.730) (total time: 1046ms):\n","stream":"stderr","time":"2022-02-15T13:59:44.778297715Z"}
{"log":"Trace[214580956]: [1.046759217s] [1.046759217s] END\n","stream":"stderr","time":"2022-02-15T13:59:44.7783034Z"}
{"log":"I0215 13:59:46.200055       1 trace.go:205] Trace[2043264468]: \"Call Audit Events webhook\" name:webhook,event-count:14 (15-Feb-2022 13:59:45.121) (total time: 1078ms):\n","stream":"stderr","time":"2022-02-15T13:59:46.200387099Z"}
{"log":"Trace[2043264468]: [1.078563449s] [1.078563449s] END\n","stream":"stderr","time":"2022-02-15T13:59:46.200412563Z"}
```

and we see new messages popping up:

```console
{"output":"2022-02-15T14:03:12.123639040+0000: Warning Request by anonymous user allowed (user=system:anonymous verb=get uri=/readyz reason=RBAC: allowed by ClusterRoleBinding \"system:public-info-viewer\" of ClusterRole \"system:public-info-viewer\" to Group \"system:unauthenticated\"))","priority":"Warning","rule":"Anonymous Request Allowed","source":"k8s_audit","tags":["k8s"],"time":"2022-02-15T14:03:12.123639040Z", "output_fields": {"jevt.time.iso8601":"2022-02-15T14:03:12.123639040+0000","ka.auth.reason":"RBAC: allowed by ClusterRoleBinding \"system:public-info-viewer\" of ClusterRole \"system:public-info-viewer\" to Group \"system:unauthenticated\"","ka.uri":"/readyz","ka.user.name":"system:anonymous","ka.verb":"get"}}
{"output":"2022-02-15T14:03:15.122832896+0000: Warning Request by anonymous user allowed (user=system:anonymous verb=get uri=/livez reason=RBAC: allowed by ClusterRoleBinding \"system:public-info-viewer\" of ClusterRole \"system:public-info-viewer\" to Group \"system:unauthenticated\"))","priority":"Warning","rule":"Anonymous Request Allowed","source":"k8s_audit","tags":["k8s"],"time":"2022-02-15T14:03:15.122832896Z", "output_fields": {"jevt.time.iso8601":"2022-02-15T14:03:15.122832896+0000","ka.auth.reason":"RBAC: allowed by ClusterRoleBinding \"system:public-info-viewer\" of ClusterRole \"system:public-info-viewer\" to Group \"system:unauthenticated\"","ka.uri":"/livez","ka.user.name":"system:anonymous","ka.verb":"get"}}
```

This is from [this rule](https://github.com/falcosecurity/charts/blob/master/falco/rules/k8s_audit_rules.yaml#L208) which confirms that the k8s audit works!
Those endpoinds are receiving some "anonymous" queries frequently; not sure why but this is interesting. Are they requested every second?

Found [this OpenShift link](http://static.open-scap.org/ssg-guides/ssg-ocp4-guide-cis.html) briefly mentioning the rule and this [issue](https://github.com/falcosecurity/falco/issues/1794) from falco which suggests we should remove those two endpoinds as they are meant to be public anyway.


## With the UI


```bash
./bootstrap_with_falcoui.sh ./values-with-ui.yaml
```

This will add falcosidekick that can send the alerts but also run a simple UI to visualise the alerts as they come in.

## Fake event generation

The falco chart also allows a fake generation in order to test the end to end process.

```bash
./bootstrap_with_falcoui.sh ./values-with-ui-and-fakegenerator.yaml
```
