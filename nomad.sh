#!/usr/bin/env bash
set -euxo pipefail

sudo apt update -y 

sudo swapoff -a

export DATACENTER="sb42"

mkdir -p /etc/certs/nomad
pushd /etc/certs/nomad

cat << EOF > /etc/certs/nomad/ca-config.json
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

cat << EOF > /etc/certs/nomad/root.json
{
    "CN": "Nomad CA",
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "names": [
        {
            "O": "Nomad"
        }
    ],
    "ca": {
        "expiry": "43800h"
    }
}
EOF

cat << EOF > /etc/certs/nomad/intermediate.json
{
    "CN": "Nomad Intermediate CA",
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "hosts": [
        "nomad-intermediate"
    ],
    "names": [
        {
            "O": "Nomad Intermediate"
        }
    ]
}
EOF

cat << EOF > /etc/certs/nomad/serving.json
{
    "hosts": [
        "server.global.nomad",
        "127.0.0.1"
    ],
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "names": [
        {
            "O":  "Nomad Serving"
        }
    ]
}
EOF

cat << EOF > /etc/certs/nomad/client.json
{
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "names": [
        {
            "O":  "Nomad Client"
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
# cp root.pem /usr/local/share/ca-certificates/nomad.crt
# cp intermediate.pem /usr/local/share/ca-certificates/intermediate.crt

# update-ca-certificates

mkdir -p /etc/nomad.d
mkdir -p /opt/nomad/templates

tee /etc/nomad.d/config.hcl > /dev/null <<EOF
datacenter = "${DATACENTER}"
data_dir = "/opt/nomad"
tls {
  http = true
  rpc  = true

  ca_file   = "/etc/certs/nomad/chain.pem"
  cert_file = "/etc/certs/nomad/server.crt"
  key_file  = "/etc/certs/nomad/server.key"

  verify_server_hostname = true
  verify_https_client    = true
}

advertise {
    http = "127.0.0.1"
    rpc  = "127.0.0.1"
    serf = "127.0.0.1"
}

client {
  enabled = true
  host_volume "dnsmasq" {
    path = "/etc/dnsmasq.d"
    read_only = false
  }
  host_volume "pihole" {
    path = "/etc/pihole"
    read_only = false
  }
}

server {
    enabled = true
    bootstrap_expect = 1
}

plugin "containerd-driver" {
  config {
    enabled = true
    containerd_runtime = "io.containerd.runc.v2"
    stats_interval = "5s"
  }
}
EOF

tee /etc/systemd/system/nomad.service > /dev/null <<EOF
[Unit]
Description=Nomad
Documentation=https://www.nomadproject.io/docs
Wants=network-online.target
After=network-online.target

[Service]
ExecReload=/bin/kill -HUP \$MAINPID
ExecStart=/usr/local/bin/nomad agent -config /etc/nomad.d/config.hcl
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

systemctl daemon-reload 
systemctl enable nomad
systemctl restart nomad

# Nomad create Nomad CA
# Cronjob every 25% of duration to generate new vault root
# -> generate new root/intermediate
# -> sign new intermediate with old root
# -> upload new intermediate and new cross intermediate to KV
# Consul auto-rotate tls
# Nomad auto-rotate tls
# Nomad upload root CA to KV
# next: check consul token works? 
