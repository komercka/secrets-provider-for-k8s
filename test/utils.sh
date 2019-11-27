#!/bin/bash
set -euo pipefail

# lookup test-env.sh.yml for explanation.
export KEY_VALUE_NOT_EXIST=" "


if [ $PLATFORM = 'kubernetes' ]; then
    cli=kubectl
elif [ $PLATFORM = 'openshift' ]; then
    cli=oc
fi

check_env_var() {
  if [[ -z "${!1+x}" ]]; then
# where ${var+x} is a parameter expansion which evaluates to nothing if var is unset, and substitutes the string x otherwise.
# https://stackoverflow.com/questions/3601515/how-to-check-if-a-variable-is-set-in-bash/13864829#13864829
    echo "You must set $1 before running these scripts."
    exit 1
  fi
}

announce() {
  echo "++++++++++++++++++++++++++++++++++++++"
  echo ""
  echo "$@"
  echo ""
  echo "++++++++++++++++++++++++++++++++++++++"
}

has_namespace() {
  if $cli get namespace  "$1" > /dev/null; then
    true
  else
    false
  fi
}

wait_for_it() {
  local timeout=$1
  local spacer=2
  shift

  if ! [ $timeout = '-1' ]; then
    local times_to_run=$((timeout / spacer))

    echo "Waiting for '$@' up to $timeout s"
    for i in $(seq $times_to_run); do
      eval $@ > /dev/null && echo 'Success!' && return 0
      echo -n .
      sleep $spacer
    done

    # Last run evaluated. If this fails we return an error exit code to caller
    eval $@
  else
    echo "Waiting for '$@' forever"

    while ! eval $@ > /dev/null; do
      echo -n .
      sleep $spacer
    done
  echo 'Success!'
  fi
}


set_namespace() {
  if [[ $# != 1 ]]; then
    printf "Error in %s/%s - expecting 1 arg.\n" "$(pwd)" $0
    exit 1
  fi

  $cli config set-context "$($cli config current-context)" --namespace="$1" > /dev/null
}

get_master_pod_name() {
  app_name=conjur-cluster
  if [ "$CONJUR_DEPLOYMENT" = "dap" ]; then
      app_name=conjur-node
  fi
  pod_list=$($cli get pods --selector app=$app_name,role=master --no-headers | awk '{ print $1 }')
  echo $pod_list | awk '{print $1}'
}

get_conjur_cli_pod_name() {
  pod_list=$($cli get pods --selector app=conjur-cli --no-headers | awk '{ print $1 }')
  echo $pod_list | awk '{print $1}'
}

function runDockerCommand() {
  docker run --rm \
    -i \
    -e UNIQUE_TEST_ID \
    -e CONJUR_VERSION \
    -e CONJUR_APPLIANCE_IMAGE \
    -e CONJUR_FOLLOWER_COUNT \
    -e CONJUR_ACCOUNT \
    -e AUTHENTICATOR_ID \
    -e CONJUR_ADMIN_PASSWORD \
    -e DEPLOY_MASTER_CLUSTER \
    -e CONJUR_NAMESPACE_NAME \
    -e PLATFORM \
    -e LOCAL_AUTHENTICATOR \
    -e TEST_APP_NAMESPACE_NAME \
    -e OPENSHIFT_URL \
    -e OPENSHIFT_USERNAME \
    -e OPENSHIFT_PASSWORD \
    -e POSTGRES_DATABASE \
    -e POSTGRES_HOSTNAME \
    -e POSTGRES_USERNAME \
    -e POSTGRES_PASSWORD \
    -e DOCKER_REGISTRY_PATH \
    -e DOCKER_REGISTRY_URL \
    -e GCLOUD_CLUSTER_NAME \
    -e GCLOUD_ZONE \
    -e GCLOUD_PROJECT_NAME \
    -e GCLOUD_SERVICE_KEY=/tmp$GCLOUD_SERVICE_KEY \
    -e MINIKUBE \
    -e MINISHIFT \
    -e CONJUR_VERSION \
    -e CONJUR_DEPLOYMENT \
    -v $GCLOUD_SERVICE_KEY:/tmp$GCLOUD_SERVICE_KEY \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v ~/.config:/root/.config \
    -v ~/.docker:/root/.docker \
    -v "$PWD/..":/src \
    -w /src \
    $TEST_RUNNER_IMAGE:$CONJUR_NAMESPACE_NAME \
    bash -c "
      ./test/platform_login.sh
      $1
    "
}

configure_cli_pod() {
  announce "Configuring Conjur CLI."

  conjur_node_name="conjur-cluster"
  if [ "$CONJUR_DEPLOYMENT" = "dap" ]; then
      conjur_node_name="conjur-master"
  fi
  conjur_url="https://$conjur_node_name.$CONJUR_NAMESPACE_NAME.svc.cluster.local"

  conjur_cli_pod=$(get_conjur_cli_pod_name)

  $cli exec $conjur_cli_pod -- bash -c "yes yes | conjur init -a $CONJUR_ACCOUNT -u $conjur_url"

  $cli exec $conjur_cli_pod -- conjur authn login -u admin -p $CONJUR_ADMIN_PASSWORD
}

function deploy_test_env {
   echo "Verifying there are no (terminating) pods of type test-env"
   wait_for_it 600 "$cli get pods --namespace=$TEST_APP_NAMESPACE_NAME --selector app=test-env --no-headers | wc -l | tr -d ' ' | grep '^0$'"

  conjur_node_name="conjur-cluster"
  if [ "$CONJUR_DEPLOYMENT" = "dap" ]; then
      conjur_node_name="conjur-follower"
  fi
  conjur_appliance_url=https://$conjur_node_name.$CONJUR_NAMESPACE_NAME.svc.cluster.local
  if [ "$CONJUR_DEPLOYMENT" = "dap" ]; then
    conjur_appliance_url="$conjur_appliance_url/api"
  fi
  conjur_authenticator_url=$conjur_appliance_url/authn-k8s/$AUTHENTICATOR_ID

  export CONJUR_APPLIANCE_URL=$conjur_appliance_url
  export CONJUR_AUTHN_URL=$conjur_authenticator_url

  echo "Deploying test-env"
  $TEST_CASES_DIR/test-env.sh.yml | $cli create -f -

  expected_num_replicas=`$TEST_CASES_DIR/test-env.sh.yml |  awk '/replicas:/ {print $2}' `

  # deploying deploymentconfig might fail on error flows, even before creating the pods. If so, retry deploy again
  if [[ "$PLATFORM" = "kubernetes" ]]; then
      wait_for_it 600 "$cli get deployment test-env -o jsonpath={.status.replicas} | grep '^${expected_num_replicas}$'|| kubectl rollout latest deployment test-env"
  elif [[ "$PLATFORM" = "openshift" ]]; then
      wait_for_it 600 "$cli get dc/test-env -o jsonpath={.status.replicas} | grep '^${expected_num_replicas}$'|| oc rollout latest dc/test-env"
  fi

  echo "Expecting for $expected_num_replicas deployed pods"
  wait_for_it 600 "$cli get pods --namespace=$TEST_APP_NAMESPACE_NAME --selector app=test-env --no-headers | wc -l | grep $expected_num_replicas"
}

function create_secret_access_role () {
  echo "Creating secrets access role"
  $TEST_CASES_DIR/secrets-access-role.sh.yml | $cli create -f -
}

function create_secret_access_role_binding () {
  echo "Creating secrets access role binding"
  $TEST_CASES_DIR/secrets-access-role-binding.sh.yml | $cli create -f -
}

function test_app_set_secret () {
  SECRET_NAME=$1
  SECRET_VALUE=$2
  echo "Set secret '$SECRET_NAME' to '$SECRET_VALUE'"
  set_namespace "$CONJUR_NAMESPACE_NAME"
  configure_cli_pod
  $cli exec $(get_conjur_cli_pod_name) -- conjur variable values add $SECRET_NAME $SECRET_VALUE
  set_namespace $TEST_APP_NAMESPACE_NAME
}

yaml_print_key_name_value () {
  spaces=$1
  key_name=${2:-""}
  key_value=${3:-""}

  if [ -z "$key_name" ]
  then
     echo ""
  else
    printf "$spaces- name: $key_name\n"
    if [ -z "$key_value" ]
    then
       echo ""
    else
       echo "$spaces  value: $key_value"
    fi
  fi
}

cli_get_pods_test_env () {
  $cli get pods --namespace=$TEST_APP_NAMESPACE_NAME --selector app=test-env --no-headers
}

verify_secret_value_in_pod () {
  pod_name=$1
  secret_name=$2
  expected_value=$3
  wait_for_it 600 $cli exec -n "$TEST_APP_NAMESPACE_NAME ${pod_name} printenv
     | grep $secret_name | cut -d '=' -f 2 | grep $expected_value"
}