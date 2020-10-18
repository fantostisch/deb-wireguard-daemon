#!/bin/bash
set -ex
rm -f "/etc/systemd/network/90-wg0.network"
rm -f "/etc/systemd/network/90-wg0.netdev"
systemctl restart systemd-networkd
rm -f ../_bin/storage.json
