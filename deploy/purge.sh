#!/bin/bash

echo ""
echo "If the daemon is still running, please stop it before running this script."
echo ""

set -ex

sudo rm -f "/etc/systemd/network/90-wg0.network"
sudo rm -f "/etc/systemd/network/90-wg0.netdev"
sudo systemctl restart systemd-networkd
sudo rm -f ../_bin/storage.json
