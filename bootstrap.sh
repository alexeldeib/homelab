#!/usr/bin/env bash
set -euxo pipefail

sudo apt update -y 

sudo swapoff -a

curl -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2020-09-01" > imds.json

export SUBSCRIPTION="$(jq -r .compute.subscriptionId /imds.json)"
export RESOURCE_GROUP="$(jq -r .compute.resourceGroupName /imds.json)"

az login -i --allow-no-subscriptions -u "/subscriptions/$SUBSCRIPTION/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.ManagedIdentity/userAssignedIdentities/vault-identity"
# az keyvault secret download --vault-name ace-vault-kv -n vault-root -f root.pem
# mkdir -p /etc/certs/vault
# openssl x509 -in root.pem -out /etc/certs/vault/server.crt
# openssl pkey -in root.pem -out /etc/certs/vault/server.key

# need this before we change $HOME later.
export TENANT_ID="$(az account show | jq -r .tenantId)"
export PRIVATE_IP="$(jq -r .network.interface[0].ipv4.ipAddress[0].privateIpAddress /imds.json)"

mkdir -p /etc/certs/vault
pushd /etc/certs/vault

cat << EOF > /etc/certs/vault/ca-config.json
{
    "signing": {
        "default": {
            "expiry": "8760h"
        },
        "profiles": {
            "intermediate": {
                "usages": [
                    "signing",
                    "digital signature",
                    "key encipherment",
                    "cert sign",
                    "crl sign",
                    "server auth",
                    "client auth"
                ],
                "expiry": "8760h",
                "ca_constraint": {
                    "is_ca": true,
                    "max_path_len": 0,
                    "max_path_len_zero": true
                }
            },
            "peer": {
                "usages": [
                    "signing",
                    "digital signature",
                    "key encipherment",
                    "client auth",
                    "server auth"
                ],
                "expiry": "8760h"
            },
            "server": {
                "usages": [
                    "signing",
                    "digital signing",
                    "key encipherment",
                    "server auth"
                ],
                "expiry": "8760h"
            },
            "client": {
                "usages": [
                    "signing",
                    "digital signature",
                    "key encipherment",
                    "client auth"
                ],
                "expiry": "8760h"
            }
        }
    }
}
EOF

cat << EOF > /etc/certs/vault/root.json
{
    "CN": "Vault CA",
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "names": [
        {
            "O": "Vault"
        }
    ],
    "ca": {
        "expiry": "43800h"
    }
}
EOF

cat << EOF > /etc/certs/vault/intermediate.json
{
    "CN": "Vault Intermediate CA",
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "hosts": [
        "vault-intermediate"
    ],
    "names": [
        {
            "O": "Vault Intermediate"
        }
    ]
}
EOF

cat << EOF > /etc/certs/vault/serving.json
{
    "hosts": [
        "vault",
        "${PRIVATE_IP}",
        "127.0.0.1"
    ],
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "names": [
        {
            "O":  "Vault Serving"
        }
    ]
}
EOF

cat << EOF > /etc/certs/vault/client.json
{
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "names": [
        {
            "O":  "Vault Client"
        }
    ]
}
EOF

cfssl genkey -initca root.json | cfssljson -bare root
cfssl gencert -ca root.pem -ca-key root-key.pem -config ca-config.json -profile intermediate intermediate.json | cfssljson -bare intermediate
cfssl gencert -ca intermediate.pem -ca-key intermediate-key.pem -config ca-config.json -profile peer serving.json | cfssljson -bare serving
cfssl gencert -ca intermediate.pem -ca-key intermediate-key.pem -config ca-config.json -profile client client.json | cfssljson -bare client
cat serving.pem intermediate.pem > chain.pem
mv serving-key.pem server.key
mv serving.pem server.crt
# cp root.pem /usr/local/share/ca-certificates/vault.crt
# cp intermediate.pem /usr/local/share/ca-certificates/intermediate.crt

# update-ca-certificates

mkdir -p /opt/vault/data
mkdir -p /opt/vault/templates
mkdir -p /etc/vault.d/
tee /etc/vault.d/vault.hcl > /dev/null <<EOF
ui = true
disable_mlock = true

api_addr = "http://${PRIVATE_IP}:8200"
cluster_addr = "http://${PRIVATE_IP}:8201"

storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = "false"
  tls_cert_file = "/etc/certs/vault/chain.pem"
  tls_key_file  = "/etc/certs/vault/server.key"
  tls_require_and_verify_client_cert = false
  telemetry {
    unauthenticated_metrics_access = true
  }
}

# enable the telemetry endpoint.
# access it at http://<VAULT-IP-ADDRESS>:8200/v1/sys/metrics?format=prometheus
# see https://www.vaultproject.io/docs/configuration/telemetry
# see https://www.vaultproject.io/docs/configuration/listener/tcp#telemetry-parameters
telemetry {
  disable_hostname = true
  prometheus_retention_time = "12h"
}

# enable auto-unseal using the azure key vault.
seal "azurekeyvault" {
  tenant_id      = "${TENANT_ID}"
  vault_name     = "ace-vault-kv"
  key_name       = "unseal-key"
}
EOF

tee /etc/systemd/system/vault.service > /dev/null <<EOF
[Unit]
Description=vault server
Requires=network-online.target

[Service]
EnvironmentFile=-/etc/default/vault
Restart=on-failure
ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 /etc/systemd/system/vault.service
systemctl daemon-reload
systemctl enable vault
systemctl start vault

sleep 15

systemctl status vault

journalctl -u vault --no-pager -n 100

ls -l /etc/certs/vault

sudo curl -v --cacert /etc/certs/vault/chain.pem --cert /etc/certs/vault/client.pem --key /etc/certs/vault/client-key.pem -v -k https://$PRIVATE_IP:8200/v1/sys/health | jq

VAULT_OPTS="-ca-cert /etc/certs/vault/chain.pem -client-cert /etc/certs/vault/server.crt -client-key /etc/certs/vault/server.key"
VAULT_STATUS="$(sudo curl --cacert /etc/certs/vault/chain.pem --cert /etc/certs/vault/client.pem --key /etc/certs/vault/client-key.pem -s -o /dev/null -w "%{http_code}" https://$PRIVATE_IP:8200/v1/sys/health)"

if [ "$VAULT_STATUS" == "501" ]; then
    vault operator init -format json -recovery-shares 1 -recovery-threshold 1 $VAULT_OPTS > init.json
elif [ "$VAULT_STATUS" != "200" ]; then
    echo "VAULT INITIALIZED AND SEALED. FAILING"
    exit 1
else
    echo "VAULT UNSEALED"
fi

export VAULT_TOKEN="$(jq -r .root_token /etc/certs/vault/init.json)"
export DATACENTER="azure-$(cat /imds.json | jq -r .compute.location)"

# Setup vault policies
mkdir -p /etc/vault.d/data
pushd /etc/vault.d/data
mkdir -p /etc/vault.d/data/sys/auth
mkdir -p /etc/vault.d/data/sys/mounts
mkdir -p /etc/vault.d/data/sys/policy
mkdir -p /etc/vault.d/data/auth/azure
mkdir -p /etc/vault.d/data/auth/azure/role
mkdir -p /etc/vault.d/data/consul_root/root/generate
mkdir -p /etc/vault.d/data/consul_root/config
mkdir -p /etc/vault.d/data/consul_intermediate/root/generate
mkdir -p /etc/vault.d/data/consul_intermediate/config 
mkdir -p /etc/vault.d/data/consul_intermediate/roles 
mkdir -p /etc/vault.d/data/nomad_root/root/generate
mkdir -p /etc/vault.d/data/nomad_root/config
mkdir -p /etc/vault.d/data/nomad_intermediate/root/generate
mkdir -p /etc/vault.d/data/nomad_intermediate/config 
mkdir -p /etc/vault.d/data/nomad_intermediate/roles 
mkdir -p /etc/vault.d/data/vault_root/root/generate
mkdir -p /etc/vault.d/data/vault_root/config
mkdir -p /etc/vault.d/data/vault_intermediate/root/generate
mkdir -p /etc/vault.d/data/vault_intermediate/config 
mkdir -p /etc/vault.d/data/vault_intermediate/roles 
mkdir -p /etc/vault.d/data/consul/config
mkdir -p /etc/vault.d/data/consul/roles
mkdir -p /etc/vault.d/data/auth/token/roles

# Auth Config

tee /etc/vault.d/data/sys/auth/azure.json > /dev/null <<EOF
{
    "type": "azure"
}
EOF

tee /etc/vault.d/data/auth/azure/config.json > /dev/null <<EOF
{
  "tenant_id": "${TENANT_ID}",
  "resource": "https://management.azure.com/"
}
EOF

tee /etc/vault.d/data/auth/azure/role/vault-server.json > /dev/null <<EOF
{
  "token_policies": ["vault-server-ca", "vault-server-pki", "vault-server-consul", "vault-server-nomad", "nomad-token"],
  "bound_subscription_ids": ["${SUBSCRIPTION}"]
}
EOF

# Policies

tee /etc/vault.d/data/sys/policy/vault-server-ca.json > /dev/null <<EOF
{
  "policy": "path \"vault*\" { capabilities = [ \"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\" ] }"
}
EOF

tee /etc/vault.d/data/sys/policy/vault-server-pki.json > /dev/null <<EOF
{
  "policy": "path \"pki*\" {\n capabilities = [ \"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\" ] \n}"
}
EOF

tee /etc/vault.d/data/sys/policy/vault-server-consul.json > /dev/null <<EOF
{
  "policy": "path \"consul*\" {\n capabilities = [ \"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\" ] \n}"
}
EOF

tee /etc/vault.d/data/sys/policy/vault-server-nomad.json > /dev/null <<EOF
{
  "policy": "path \"nomad*\" {\n capabilities = [ \"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\" ] \n}"
}
EOF

tee /etc/vault.d/data/sys/policy/nomad-token.json<<EOF
{
  "policy": "path \"auth/token/create/nomad-cluster\" {\n capabilities = [\"update\"] \n}\npath \"auth/token/roles/nomad-cluster\" {\n capabilities = [\"read\"] \n}\npath \"auth/token/lookup-self\" {\n capabilities = [\"read\"] \n}\npath \"auth/token/lookup\" {\n capabilities = [\"update\"] \n}\npath \"auth/token/revoke-accessor\" {\n capabilities = [\"update\"] \n}\npath \"sys/capabilities-self\" {\n capabilities = [\"update\"] \n}\npath \"auth/token/renew-self\" {\n capabilities = [\"update\"] \n}"
}
EOF

# Mounts 

tee /etc/vault.d/data/sys/mounts/vault_root.json > /dev/null <<EOF
{
    "type": "pki",
    "config": {
        "max_lease_ttl": "8760h"
    }
}
EOF

tee /etc/vault.d/data/sys/mounts/vault_intermediate.json > /dev/null <<EOF
{
    "type": "pki",
    "config": {
        "max_lease_ttl": "4380h"
    }
}
EOF

tee /etc/vault.d/data/sys/mounts/consul_root.json > /dev/null <<EOF
{
    "type": "pki",
    "config": {
        "max_lease_ttl": "8760h"
    }
}
EOF

tee /etc/vault.d/data/sys/mounts/consul_intermediate.json > /dev/null <<EOF
{
    "type": "pki",
    "config": {
        "max_lease_ttl": "4380h"
    }
}
EOF

# Vault Root CA

tee /etc/vault.d/data/vault_root/root/generate/internal.json > /dev/null <<EOF
{
    "common_name": "${DATACENTER}.vault",
    "ttl": "8760h"
}
EOF

tee /etc/vault.d/data/vault_root/config/urls.json > /dev/null <<EOF
{
    "issuing_certificates": "http://127.0.0.1:8200/v1/pki/ca",
    "crl_distribution_points": "http://127.0.0.1:8200/v1/pki/crl"
}
EOF

# Vault Intermediate CA

tee /etc/vault.d/data/vault_intermediate/root/generate/internal.json > /dev/null <<EOF
{
    "common_name": "${DATACENTER}.vault",
    "ttl": "4380h"
}
EOF

tee /etc/vault.d/data/vault_intermediate/config/urls.json > /dev/null <<EOF
{
    "issuing_certificates": "http://127.0.0.1:8200/v1/pki/ca",
    "crl_distribution_points": "http://127.0.0.1:8200/v1/pki/crl"
}
EOF

tee /etc/vault.d/data/vault_intermediate/roles/${DATACENTER}.vault.json > /dev/null <<EOF
{
    "allowed_domains": "${DATACENTER}.vault",
    "allow_subdomains": true,
    "generate_lease": true,
    "ttl": "720h"
}
EOF

# Consul Root CA

tee /etc/vault.d/data/consul_root/root/generate/internal.json > /dev/null <<EOF
{
    "common_name": "${DATACENTER}.consul",
    "ttl": "8760h"
}
EOF

tee /etc/vault.d/data/consul_root/config/urls.json > /dev/null <<EOF
{
    "issuing_certificates": "http://127.0.0.1:8200/v1/pki/ca",
    "crl_distribution_points": "http://127.0.0.1:8200/v1/pki/crl"
}
EOF

# Consul Intermediate CA

tee /etc/vault.d/data/consul_intermediate/root/generate/internal.json > /dev/null <<EOF
{
    "common_name": "${DATACENTER}.consul",
    "ttl": "4380h"
}
EOF

tee /etc/vault.d/data/consul_intermediate/config/urls.json > /dev/null <<EOF
{
    "issuing_certificates": "http://127.0.0.1:8200/v1/pki/ca",
    "crl_distribution_points": "http://127.0.0.1:8200/v1/pki/crl"
}
EOF

tee /etc/vault.d/data/consul_intermediate/roles/${DATACENTER}.consul.json > /dev/null <<EOF
{
    "allowed_domains": "${DATACENTER}.consul",
    "allow_subdomains": true,
    "generate_lease": true,
    "ttl": "720h"
}
EOF

# Nomad Root CA

tee /etc/vault.d/data/sys/mounts/nomad_root.json > /dev/null <<EOF
{
    "type": "pki",
    "config": {
        "max_lease_ttl": "8760h"
    }
}
EOF

tee /etc/vault.d/data/sys/mounts/nomad_intermediate.json > /dev/null <<EOF
{
    "type": "pki",
    "config": {
        "max_lease_ttl": "4380h"
    }
}
EOF

tee /etc/vault.d/data/sys/mounts/consul.json > /dev/null <<EOF
{
    "type": "consul",
    "config": {
        "max_lease_ttl": "8760h"
    }
}
EOF

tee /etc/vault.d/data/consul/roles/consul-server.json > /dev/null <<EOF
{
    "policies": ["node-policy"]
}
EOF

tee /etc/vault.d/data/nomad_root/root/generate/internal.json > /dev/null <<EOF
{
    "common_name": "${DATACENTER}.nomad",
    "ttl": "8760h"
}
EOF

tee /etc/vault.d/data/nomad_root/config/urls.json > /dev/null <<EOF
{
    "issuing_certificates": "http://127.0.0.1:8200/v1/pki/ca",
    "crl_distribution_points": "http://127.0.0.1:8200/v1/pki/crl"
}
EOF

tee /etc/vault.d/data/nomad_intermediate/root/generate/internal.json > /dev/null <<EOF
{
    "common_name": "${DATACENTER}.nomad",
    "ttl": "4380h"
}
EOF

tee /etc/vault.d/data/nomad_intermediate/config/urls.json > /dev/null <<EOF
{
    "issuing_certificates": "http://127.0.0.1:8200/v1/pki/ca",
    "crl_distribution_points": "http://127.0.0.1:8200/v1/pki/crl"
}
EOF

tee /etc/vault.d/data/nomad_intermediate/roles/${DATACENTER}.nomad.json > /dev/null <<EOF
{
    "allowed_domains": "${DATACENTER}.nomad",
    "allow_subdomains": true,
    "generate_lease": true,
    "ttl": "720h"
}
EOF

tee /etc/vault.d/data/auth/token/roles/nomad-cluster.json > /dev/null <<EOF
{
  "disallowed_policies": "nomad-server",
  "token_explicit_max_ttl": 0,
  "name": "nomad-cluster",
  "orphan": true,
  "token_period": 259200,
  "renewable": true
}
EOF

function provision() {
  for f in $(ls "${1}"/*.json); do
    p="${f%.json}"
    echo "Provisioning $p"
    curl \
        --cacert /etc/certs/vault/chain.pem \
        --location \
        --header "X-Vault-Token: ${VAULT_TOKEN}" \
        --data @"${p}.json" \
        "https://127.0.0.1:8200/v1/${p}"
        # --cert /etc/certs/vault/client.pem \
        # --key /etc/certs/vault/client-key.pem \
  done
}

export VAULT_TOKEN="$(jq -r .root_token /etc/certs/vault/init.json)"

provision sys/auth
provision sys/policy
provision sys/mounts
provision auth/azure
provision auth/azure/role
provision vault_root/root/generate
provision vault_root/config
provision vault_intermediate/config
provision vault_intermediate/roles
provision consul_root/root/generate
provision consul_root/config
provision consul_intermediate/config
provision consul_intermediate/roles
provision nomad_root/root/generate
provision nomad_root/config
provision nomad_intermediate/config
provision nomad_intermediate/roles
provision consul/roles
provision auth/token/roles

vault write $VAULT_OPTS -format=json vault_intermediate/intermediate/generate/internal common_name="${DATACENTER}.vault Intermediate Authority" | jq -r '.data.csr' > vault_intermediate.csr
vault write $VAULT_OPTS -format=json vault_root/root/sign-intermediate csr=@vault_intermediate.csr format=pem_bundle ttl="4380h" | jq -r '.data.certificate' > vault_intermediate.pem
vault write $VAULT_OPTS vault_intermediate/intermediate/set-signed certificate=@vault_intermediate.pem

mkdir -p /etc/certs/vault
vault write $VAULT_OPTS -format=json vault_intermediate/issue/${DATACENTER}.vault common_name="server.${DATACENTER}.vault" ttl="24h" ip_sans="127.0.0.1,${PRIVATE_IP}" > /etc/certs/vault/out.json
jq -r .data.certificate /etc/certs/vault/out.json > /etc/certs/vault/server.crt
jq -r .data.private_key /etc/certs/vault/out.json > /etc/certs/vault/server.key
jq -r .data.issuing_ca /etc/certs/vault/out.json > /etc/certs/vault/ca.crt
cat /etc/certs/vault/server.crt /etc/certs/vault/ca.crt > /etc/certs/vault/chain.pem
systemctl restart vault
sleep 10

# Bootstrap consul

vault write $VAULT_OPTS -format=json consul_intermediate/intermediate/generate/internal common_name="${DATACENTER}.consul Intermediate Authority" | jq -r '.data.csr' > consul_intermediate.csr
vault write $VAULT_OPTS -format=json consul_root/root/sign-intermediate csr=@consul_intermediate.csr format=pem_bundle ttl="4380h" | jq -r '.data.certificate' > consul_intermediate.pem
vault write $VAULT_OPTS consul_intermediate/intermediate/set-signed certificate=@consul_intermediate.pem

mkdir -p /etc/certs/consul
vault write $VAULT_OPTS -format=json consul_intermediate/issue/${DATACENTER}.consul common_name="server.${DATACENTER}.consul" ttl="24h" ip_sans="127.0.0.1,${PRIVATE_IP}" > /etc/certs/consul/out.json
jq -r .data.certificate /etc/certs/consul/out.json > /etc/certs/consul/server.crt
jq -r .data.private_key /etc/certs/consul/out.json > /etc/certs/consul/server.key
jq -r .data.issuing_ca /etc/certs/consul/out.json > /etc/certs/consul/ca.crt

# Setup consul
mkdir -p /opt/consul/templates
mkdir -p /opt/consul/data
mkdir -p /etc/consul.d

consul keygen > /etc/certs/consul/gossip.key
tee /etc/consul.d/config.json > /dev/null <<EOF
{
    "datacenter": "${DATACENTER}",
    "data_dir": "/opt/consul/data",
    "log_level": "INFO",
    "node_name": "$(hostname)",
    "server": true,
    "client_addr": "0.0.0.0",
    "addresses": {
        "https": "0.0.0.0"
    },
    "ports": {
        "http": -1,
        "https": 8501
    },
    "encrypt": "$(cat /etc/certs/consul/gossip.key)",
    "verify_incoming": true,
    "verify_outgoing": true,
    "verify_server_hostname": true,
    "key_file": "/etc/certs/consul/server.key",
    "cert_file": "/etc/certs/consul/server.crt",
    "ca_file": "/etc/certs/consul/ca.crt",
    "auto_encrypt": {
        "allow_tls": true
    },
    "acl": {
        "enabled": true,
        "default_policy": "deny",
        "enable_token_persistence": true
    }
}
EOF

tee /etc/systemd/system/consul.service > /dev/null <<EOF
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/config.json

[Service]
Type=exec
ExecStart=/usr/local/bin/consul agent -server -bootstrap-expect 1 -bind '{{ GetPrivateInterfaces | include "network" "10.0.0.0/8" | attr "address" }}' -config-file=/etc/consul.d/config.json
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
KillSignal=SIGTERM
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

tee /etc/consul.d/node-policy.hcl > /dev/null <<EOF
agent_prefix "" {
  policy = "write"
}
node_prefix "" {
  policy = "write"
}
service_prefix "" {
  policy = "read"
}
session_prefix "" {
  policy = "read"
}
EOF

systemctl daemon-reload 
systemctl enable consul
systemctl restart consul

sleep 10

consul acl bootstrap -http-addr https://127.0.0.1:8501 -ca-file /etc/certs/consul/ca.crt -client-cert /etc/certs/consul/server.crt -client-key /etc/certs/consul/server.key -format=json > /etc/consul.d/acl.bootstrap.json
export CONSUL_HTTP_TOKEN="$(jq -r .SecretID /etc/consul.d/acl.bootstrap.json)"
export CONSUL_MGMT_TOKEN="$(jq -r .SecretID /etc/consul.d/acl.bootstrap.json)"
consul acl policy create -http-addr https://127.0.0.1:8501 -ca-file /etc/certs/consul/ca.crt -client-cert /etc/certs/consul/server.crt -client-key /etc/certs/consul/server.key -token=${CONSUL_MGMT_TOKEN} -name node-policy -rules @/etc/consul.d/node-policy.hcl

tee /etc/vault.d/data/consul/config/access.json > /dev/null <<EOF
{
    "scheme": "https",
    "address": "127.0.0.1:8501",
    "token": "${CONSUL_HTTP_TOKEN}",
    "ca_cert": "$(cat /etc/certs/consul/ca.crt | awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}')",
    "client_cert": "$(cat /etc/certs/consul/server.crt | awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}')",
    "client_key": "$(cat /etc/certs/consul/server.key | awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}')"
}
EOF

provision consul/config

# Setup nomad
vault write $VAULT_OPTS -format=json nomad_intermediate/intermediate/generate/internal common_name="${DATACENTER}.nomad Intermediate Authority" | jq -r '.data.csr' > nomad_intermediate.csr
vault write $VAULT_OPTS -format=json nomad_root/root/sign-intermediate csr=@nomad_intermediate.csr format=pem_bundle ttl="4380h" | jq -r '.data.certificate' > nomad_intermediate.pem
vault write $VAULT_OPTS nomad_intermediate/intermediate/set-signed certificate=@nomad_intermediate.pem

mkdir -p /etc/certs/nomad
vault write $VAULT_OPTS -format=json nomad_intermediate/issue/${DATACENTER}.nomad common_name="server.${DATACENTER}.nomad" ttl="24h" ip_sans="127.0.0.1,${PRIVATE_IP}" > /etc/certs/nomad/out.json
jq -r .data.certificate /etc/certs/nomad/out.json > /etc/certs/nomad/server.crt
jq -r .data.private_key /etc/certs/nomad/out.json > /etc/certs/nomad/server.key
jq -r .data.issuing_ca /etc/certs/nomad/out.json > /etc/certs/nomad/ca.crt

mkdir -p /etc/nomad.d
mkdir -p /opt/nomad/templates

tee /etc/nomad.d/config.hcl > /dev/null <<EOF
datacenter = "${DATACENTER}"
data_dir = "/opt/nomad"
tls {
  http = true
  rpc  = true

  ca_file   = "/etc/certs/nomad/ca.crt"
  cert_file = "/etc/certs/nomad/server.crt"
  key_file  = "/etc/certs/nomad/server.key"

  verify_server_hostname = true
  verify_https_client    = true
}

vault {
  enabled = true
  address = "https://127.0.0.1:8200"
  task_token_ttl = "1h"
  create_from_role = "nomad-cluster"
  ca_file   = "/etc/certs/vault/chain.pem"
  cert_file = "/etc/certs/vault/server.crt"
  key_file  = "/etc/certs/vault/server.key"
}

server {
    enabled = true
    bootstrap_expect = 1
}
EOF

tee /etc/systemd/system/nomad.service > /dev/null <<EOF
[Unit]
Description=Nomad
Documentation=https://www.nomadproject.io/docs
Wants=network-online.target
Wants=vault-agent.service
After=network-online.target
After=vault-agent.service

[Service]
ExecReload=/bin/kill -HUP \$MAINPID
ExecStart=/opt/nomad/start.sh
KillMode=process
KillSignal=SIGTERM
LimitNOFILE=infinity
LimitNPROC=infinity
Restart=on-failure
RestartSec=3
StartLimitBurst=3
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

tee /opt/nomad/start.sh > /dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ -f /tmp/vault-agent-token ]; then
    exec env VAULT_TOKEN="$(cat /tmp/vault-agent-token)" \
        /usr/local/bin/nomad agent -config /etc/nomad.d/config.hcl
else
    echo "Nomad failed to start due to missing vault agent token"
    exit 1
fi
EOF

chmod a+x /opt/nomad/start.sh

systemctl daemon-reload 
systemctl enable nomad
systemctl restart nomad


mkdir -p /etc/vault-agent.d

tee /etc/systemd/system/vault-agent.service > /dev/null <<EOF
[Unit]
Description=vault agent
Requires=network-online.target

[Service]
Restart=on-failure
ExecStart=/usr/local/bin/vault agent -config=/etc/vault-agent.d/config.hcl

[Install]
WantedBy=multi-user.target
EOF

tee /etc/vault-agent.d/config.hcl > /dev/null <<EOF
vault {
  ca_cert = "/etc/certs/vault/chain.pem"
}

auto_auth {
  method {
    type      = "azure"
    config = {
      role = "vault-server"
      resource = "https://management.azure.com/"
    }
  }

  sink {
    type = "file"
    config = {
      path = "/tmp/vault-agent-token"
    }
  }
}
EOF

systemctl enable vault-agent
systemctl restart vault-agent

mkdir -p /etc/consul-template.d
tee /etc/default/consul-template > /dev/null <<EOF
/etc/default/consul-template
EOF

tee /etc/systemd/system/consul-template.service > /dev/null <<EOF
[Unit]
Description=consul-template
Requires=network-online.target
After=network-online.target consul.service vault.service

[Service]
EnvironmentFile=-/etc/default/consul-template
KillSignal=SIGINT
Restart=on-failure
ExecStart=/usr/local/bin/consul-template -config=/etc/consul-template.d/nomad-certs.hcl

[Install]
WantedBy=multi-user.target
EOF

tee /etc/consul-template.d/nomad-certs.hcl > /dev/null <<EOF
vault {
  address      = "https://127.0.0.1:8200"

  unwrap_token = false
  renew_token  = true
  vault_agent_token_file = "/tmp/vault-agent-token"

  ssl {
    enabled = true
    verify = true
    ca_path  = "/etc/certs/vault/chain.pem"
  }
}

template {
  source      = "/opt/nomad/templates/server.crt.tpl"
  destination = "/etc/certs/nomad/server.crt"
  perms       = 0700
  command     = "systemctl restart nomad"
}

template {
  source      = "/opt/nomad/templates/server.key.tpl"
  destination = "/etc/certs/nomad/server.key"
  perms       = 0700
  command     = "systemctl restart nomad"
}

template {
  source      = "/opt/nomad/templates/ca.crt.tpl"
  destination = "/etc/certs/nomad/ca.crt"
  command     = "systemctl restart nomad"
}

template {
  source      = "/opt/consul/templates/tls.json.tpl"
  destination = "/etc/certs/consul/tls.json"
  perms       = 0700
  command     = "bash -c '/opt/consul/templates/script-update.sh'"
}

template {
  source      = "/opt/vault/templates/tls.json.tpl"
  destination = "/etc/certs/vault/tls.json"
  perms       = 0700
  command     = "bash -c '/opt/vault/templates/script-update.sh'"
}
EOF

tee /opt/nomad/templates/server.crt.tpl > /dev/null <<EOF
{{ with secret "nomad_intermediate/issue/${DATACENTER}.nomad" "common_name=server.${DATACENTER}.nomad" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1,${PRIVATE_IP}" }}
{{ .Data.certificate }}
{{ end }}
EOF

tee /opt/nomad/templates/server.key.tpl > /dev/null <<EOF
{{ with secret "nomad_intermediate/issue/${DATACENTER}.nomad" "common_name=server.${DATACENTER}.nomad" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1,${PRIVATE_IP}" }}
{{ .Data.private_key }}
{{ end }}
EOF

tee /opt/nomad/templates/ca.crt.tpl > /dev/null <<EOF
{{ with secret "nomad_intermediate/issue/${DATACENTER}.nomad" "common_name=server.${DATACENTER}.nomad" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1,${PRIVATE_IP}" }}
{{ .Data.issuing_ca }}
{{ end }}
EOF

tee /opt/consul/templates/tls.json.tpl > /dev/null <<EOF
{{- with secret "consul_intermediate/issue/${DATACENTER}.consul" "common_name=server.${DATACENTER}.consul" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1,${PRIVATE_IP}" -}}
{{- .Data | toJSONPretty -}}
{{- end -}}
EOF

tee /opt/vault/templates/tls.json.tpl > /dev/null <<EOF
{{- with secret "vault_intermediate/issue/${DATACENTER}.vault" "common_name=server.${DATACENTER}.vault" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1,${PRIVATE_IP}" -}}
{{- .Data | toJSONPretty -}}
{{- end -}}
EOF

tee /opt/vault/templates/script-update.sh > /dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CERT="$(jq -r .certificate "/etc/certs/vault/tls.json")"
KEY="$(jq -r .private_key "/etc/certs/vault/tls.json")"
CA="$(jq -r .issuing_ca "/etc/certs/vault/tls.json")"

echo "$CERT" > /etc/certs/vault/server.crt
echo "$KEY" > /etc/certs/vault/server.key
echo "$CA" > /etc/certs/vault/ca.crt
cat /etc/certs/vault/server.crt /etc/certs/vault/ca.crt > /etc/certs/vault/chain.pem
systemctl restart vault
EOF

tee /opt/consul/templates/script-update.sh > /dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CERT="$(jq -r .certificate "/etc/certs/consul/tls.json")"
KEY="$(jq -r .private_key "/etc/certs/consul/tls.json")"
CA="$(jq -r .issuing_ca "/etc/certs/consul/tls.json")"

echo "$CERT" > /etc/certs/consul/server.crt
echo "$KEY" > /etc/certs/consul/server.key
echo "$CA" > /etc/certs/consul/ca.crt

ACCESS_CONFIG="/etc/vault.d/data/consul/config/access.json"
jq -r --arg CA "$CA" '.ca_cert = $CA' "$ACCESS_CONFIG" > tmp.json
mv tmp.json "$ACCESS_CONFIG"

if [ -f /tmp/vault-agent-token ]; then
    export VAULT_TOKEN="$(cat /tmp/vault-agent-token)"
else
    echo "Nomad failed to start due to missing vault agent token"
    exit 1
fi

vault write -ca-cert /etc/certs/vault/chain.pem consul/config/access address="$(jq -r .address "$ACCESS_CONFIG")" scheme="$(jq -r .scheme "$ACCESS_CONFIG")" token="$(jq -r .token "$ACCESS_CONFIG")" ca_cert="$(jq -r .ca_cert "$ACCESS_CONFIG")" client_cert="$(jq -r .client_cert "$ACCESS_CONFIG")" client_key="$(jq -r .client_key "$ACCESS_CONFIG")"
systemctl restart consul
EOF

chmod a+x /opt/vault/templates/script-update.sh
chmod a+x /opt/consul/templates/script-update.sh

# tee /opt/vault/templates/server.crt.tpl > /dev/null <<EOF
# {{ with secret "vault_intermediate/issue/${DATACENTER}.vault" "common_name=server.${DATACENTER}.vault" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1,${PRIVATE_IP}" }}
# {{ .Data.certificate }}
# {{ end }}
# EOF

# tee /opt/vault/templates/server.key.tpl > /dev/null <<EOF
# {{ with secret "vault_intermediate/issue/${DATACENTER}.vault" "common_name=server.${DATACENTER}.vault" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1,${PRIVATE_IP}" }}
# {{ .Data.private_key }}
# {{ end }}
# EOF

# tee /opt/vault/templates/ca.crt.tpl > /dev/null <<EOF
# {{ with secret "vault_intermediate/issue/${DATACENTER}.vault" "common_name=server.${DATACENTER}.vault" "ttl=24h" "alt_names=localhost" "ip_sans=127.0.0.1,${PRIVATE_IP}" }}
# {{ .Data.issuing_ca }}
# {{ end }}
# EOF

systemctl enable consul-template
systemctl restart consul-template

# Vault create Vault CA
# Cronjob every 25% of duration to generate new vault root
# -> generate new root/intermediate
# -> sign new intermediate with old root
# -> upload new intermediate and new cross intermediate to KV
# Consul auto-rotate tls
# Nomad auto-rotate tls
# Vault upload root CA to KV
# next: check consul token works? 
