###############################################################################
# NETWORK
###############################################################################

cat <<EOF >/etc/sysctl.d/70-vpn.conf
net.ipv4.ip_forward = 1
EOF

sysctl --system
