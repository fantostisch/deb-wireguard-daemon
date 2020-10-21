#!/bin/bash

echo ""
echo "If the daemon is still running, please stop it before running this script."
echo ""

set -ex

rm -f "/etc/systemd/network/90-wg0.network"
rm -f "/etc/systemd/network/90-wg0.netdev"
systemctl restart systemd-networkd
rm -f ../_bin/storage.json
