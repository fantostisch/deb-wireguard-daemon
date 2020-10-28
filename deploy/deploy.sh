#!/bin/bash
set -ex

###############################################################################
# SOFTWARE
###############################################################################
apt-get update
apt-get -y install linux-headers-"$(dpkg --print-architecture)"
sudo apt-get -y install golang-1.14-go
sudo apt-get install wireguard
apt-get install -y iproute2

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

cp ./wg0.netdev "$netdev_file"
chown root:systemd-network "$netdev_file"
chmod 0640 "$netdev_file"

set +x
echo "PrivateKey=$private_key" >> "$netdev_file"
set -x

listen_port=$1
if [ -z "$listen_port" ]; then
  listen_port=51820
fi
echo "ListenPort=$listen_port" >> "$netdev_file"

cp ./wg0.network /etc/systemd/network/90-wg0.network

systemctl enable systemd-networkd
systemctl restart systemd-networkd

echo "Deployed successfully, a reboot might be necessary if the linux kernel headers were not already installed."
