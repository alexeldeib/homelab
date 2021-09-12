#!/usr/bin/env bash
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive

sudo apt update -y && sudo apt install -y apt-transport-https curl git gnupg build-essential lsb-release jq flex bison libelf-dev libssl-dev openssl
sudo swapoff -a

curl -sL https://packages.microsoft.com/keys/microsoft.asc | \
    gpg --dearmor | \
    sudo tee /etc/apt/trusted.gpg.d/microsoft.asc.gpg > /dev/null

AZ_REPO=$(lsb_release -cs)
echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" | \
    sudo tee /etc/apt/sources.list.d/azure-cli.list

sudo apt-get update
sudo apt-get install -y azure-cli < /dev/null

# Install Golang
GOLANG_VERSION=1.16
curl -O https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz
sudo tar -xvf go${GOLANG_VERSION}.linux-amd64.tar.gz -C /usr/local > /dev/null

mkdir -p /home/packer
touch /home/packer/.bashrc
tee -a /home/packer/.bashrc > /dev/null <<'EOF'
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:/home/packer/go/bin
export GOPATH=/home/packer/go
EOF

export GOPATH=/home/packer/go
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:/home/packer/go/bin

mkdir -p $GOPATH/src/github.com/hashicorp
mkdir -p $GOPATH/src/github.com/cloudflare
pushd $GOPATH/src/github.com/hashicorp

git clone https://github.com/hashicorp/consul
git clone https://github.com/hashicorp/consul-template
git clone https://github.com/hashicorp/vault
git clone https://github.com/hashicorp/nomad

export HOME=/home/packer

echo "Building vault..."
pushd vault
make -j$(nproc) bootstrap
make -j$(nproc) dev
chmod a+x bin/vault 
sudo mv bin/vault /usr/local/bin/vault
popd

echo "Building consul..."
pushd consul
make -j$(nproc) tools
make -j$(nproc) dev
chmod a+x bin/consul 
sudo mv bin/consul /usr/local/bin/consul
popd

echo "Building nomad..."
pushd nomad
make -j$(nproc) deps
make -j$(nproc) dev
chmod a+x bin/nomad 
sudo mv bin/nomad /usr/local/bin/nomad
popd


echo "Building consul-template..."
pushd consul-template
make -j$(nproc) dev
chmod a+x $GOPATH/bin/consul-template 
sudo mv $GOPATH/bin/consul-template /usr/local/bin/consul-template
popd

# leave GOPATH
popd

echo "Successfully built all hashi apps!"

echo "Building cfssl..."

pushd $GOPATH/src/github.com/cloudflare
git clone https://github.com/cloudflare/cfssl
cd cfssl
make -j$(nproc)
chmod a+x bin/*
sudo mv bin/* /usr/local/bin/
popd

echo "Successfully built cfssl"

echo "Testing invocations"

vault || true

nomad || true

consul || true
