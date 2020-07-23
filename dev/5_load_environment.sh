#!/bin/bash
set -euxo pipefail

. ../common/utils.sh

function main() {
  ./teardown_resources.sh

  set_namespace "$APP_NAMESPACE_NAME"

  configure_secret

  deploy_env
}

function configure_secret() {
  announce "Configuring K8s Secret and access."

  export ENV_DIR="$PWD/config/k8s"
  if [[ "$PLATFORM" = "openshift" ]]; then
      export ENV_DIR="$PWD/config/openshift"
  fi

  echo "Create secret k8s-secret"
  $cli_with_timeout create -f $ENV_DIR/k8s-secret.yml

  create_secret_access_role

  create_secret_access_role_binding
}

main
