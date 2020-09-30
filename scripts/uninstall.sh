#!/bin/sh
WG_INTERFACE="$1"
ip link set down "$WG_INTERFACE"
