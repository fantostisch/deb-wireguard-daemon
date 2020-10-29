#!/bin/bash
set -ex

###############################################################################
# SOFTWARE
###############################################################################
sudo apt-get update
sudo apt-get -y install linux-headers-"$(dpkg --print-architecture)"
sudo apt-get -y install golang-go
sudo apt-get install wireguard
sudo apt-get install -y iproute2

###############################################################################
# Keys
###############################################################################
set +x
private_key=$(wg genkey)
public_key=$(echo "$private_key" | wg pubkey)
set -x

###############################################################################
# Storage
###############################################################################
../_bin/wireguard-daemon --init --storage-file ../_bin/storage.json --publicKey "$public_key"

###############################################################################
# systemd
###############################################################################
netdev_file="/etc/systemd/network/90-wg0.netdev"

sudo cp ./wg0.netdev "$netdev_file"
sudo chown root:systemd-network "$netdev_file"
sudo chmod 0640 "$netdev_file"

set +x
echo "PrivateKey=$private_key" | (sudo tee -a "$netdev_file" > /dev/null)
set -x

listen_port=$1
if [ -z "$listen_port" ]; then
  listen_port=51820
fi
echo "ListenPort=$listen_port" | (sudo tee -a "$netdev_file" > /dev/null)

sudo cp ./wg0.network /etc/systemd/network/90-wg0.network

sudo systemctl enable systemd-networkd
sudo systemctl restart systemd-networkd

echo "Deployed successfully, a reboot might be necessary if the linux kernel headers were not already installed."
