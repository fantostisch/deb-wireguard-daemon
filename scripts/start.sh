#!/bin/sh
WG_INTERFACE="$1"
ip link set up "$WG_INTERFACE"
