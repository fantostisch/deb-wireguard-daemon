#!/bin/bash
set -e

private_key=$(wg genkey)
public_key=$(echo "$private_key" | wg pubkey)

set -x

../_bin/wireguard-daemon --init --storage-file ../_bin/storage.json --publicKey "$public_key"

###############################################################################
# NETWORK
###############################################################################
netdev_file="/etc/systemd/network/90-wg0.netdev"

cp ./wg0.netdev "$netdev_file"
chown root:systemd-network "$netdev_file"
chmod 0640 "$netdev_file"

set +x
echo "PrivateKey=$private_key" >>"$netdev_file"
set -x

cp ./wg0.network /etc/systemd/network/90-wg0.network

systemctl enable systemd-networkd
systemctl restart systemd-networkd
