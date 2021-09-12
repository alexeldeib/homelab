#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

IMDS_JSON="$(curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2017-08-01")"

vault write -ca-cert /etc/certs/vault/chain.pem auth/azure/login role="vault-server" \
    jwt="$(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F' -H Metadata:true | jq -r '.access_token')" \
    subscription_id=$(echo "$IMDS_JSON" | jq -r '.compute | .subscriptionId')  \
    resource_group_name=$(echo "$IMDS_JSON" | jq -r '.compute | .resourceGroupName') \
    vm_name=$(echo "$IMDS_JSON" | jq -r '.compute | .name')

rm imds.json
