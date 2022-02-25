#!/bin/bash

VALUES_FILE="values.yaml"

if [[ $# -eq "1" ]]; then
  VALUES_FILE=$1
fi

minikube start --cpus 4 --memory 8GiB

helm install falco --values "${VALUES_FILE}" falcosecurity/falco --wait

if [[ ! -d "evolution" ]]; then
  git clone git@github.com:falcosecurity/evolution.git
fi

pushd ./evolution/examples/k8s_audit_config || exit 1
FALCO_SERVICE_CLUSTERIP=$(kubectl get service falco -o='jsonpath={.spec.clusterIP}') envsubst < webhook-config.yaml.in > webhook-config.yaml
bash enable-k8s-audit.sh minikube static

popd || exit 1

sleep 90


if kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=falco-ui --timeout=60s; then
  # there's a UI to look at
  url=$(minikube service falco-falcosidekick-ui --url || exit 1)/ui
  echo "${url}"
fi
