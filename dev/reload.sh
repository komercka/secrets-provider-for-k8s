#!/bin/bash
set -xeuo pipefail

. ../common/utils.sh

# Script for making it easy to make a change locally and redeploy
pushd ..
  ./bin/build
popd

set_namespace $APP_NAMESPACE_NAME

docker tag "secrets-provider-for-k8s:dev" "${APP_NAMESPACE_NAME}/secrets-provider"

selector="role=follower"
cert_location="/opt/conjur/etc/ssl/conjur.pem"
if [ "$CONJUR_DEPLOYMENT" = "oss" ]; then
  selector="app=conjur-cli"
  cert_location="/root/conjur-${CONJUR_ACCOUNT}.pem"
fi

conjur_pod_name=$($cli_with_timeout get pods --selector=$selector --namespace $CONJUR_NAMESPACE_NAME --no-headers | awk '{ print $1 }' | head -1)
ssl_cert=$($cli_with_timeout "exec ${conjur_pod_name} --namespace $CONJUR_NAMESPACE_NAME cat $cert_location")

export CONJUR_SSL_CERTIFICATE=$ssl_cert

export ENV_DIR="$PWD/config/k8s"
if [[ "$PLATFORM" = "openshift" ]]; then
  export ENV_DIR="$PWD/config/openshift"
fi

$cli_with_timeout "delete deployment init-env --ignore-not-found=true"

deploy_env