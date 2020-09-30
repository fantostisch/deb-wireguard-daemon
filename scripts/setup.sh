#!/bin/sh
WG_INTERFACE="$1"
ip link add "$WG_INTERFACE" type wireguard
ip address add dev "$WG_INTERFACE" 10.0.0.0/8
