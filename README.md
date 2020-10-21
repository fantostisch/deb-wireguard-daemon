# WireGuard Daemon

Daemon for managing a WireGuard server using an API.
Built for [eduVPN](https://eduvpn.org).

This project is used by the
[eduVPN portal with WireGuard support](https://github.com/fantostisch/vpn-user-portal).

## API endpoints overview

| Method | URL                         | POST Data                              | Description                                                                                                  |
|--------|-----------------------------|----------------------------------------|--------------------------------------------------------------------------------------------------------------|
| GET    | /configs?user_id=foo        |                                        | List all configs of the user. Return empty list if no configs found.                                         |
| POST   | /create_config              | user_id=foo&public_key=ABC&name=Laptop | Create client config. Creating 2 client configs with the same public key will overwrite the existing config. |
| POST   | /create_config_and_key_pair | user_id=foo&name=Phone                 | Create client config. Let the server create a public private key pair.                                       |
| POST   | /delete_config              | user_id=foo&public_key=ABC             | Delete client config. 409 if config not found.                                                               |
| GET    | /client_connections         |                                        | Get clients that successfully send or received a packet in the last 3 minutes.                               |
| POST   | /disable_user               | user_id=foo                            | Disable user. 409 if user is already disabled.                                                               |
| POST   | /enable_user                | user_id=foo                            | Enable user. 409 if user is already enabled.                                                                 |

todo: document return values including errors

## Compatibility

### Debian 10 (Buster)
WireGuard, Go and systemd must be installed from backports, which needs to be enabled. [Instructions for enabling backports on Debian](https://backports.debian.org/Instructions/).
```sh
sudo apt install -t buster-backports wireguard golang-1.14-go systemd
```

### Completely working
* Debian 11 (Bullseye)
* Debian Unstable (Sid)

## Installation

### Set-up Go global variables

Add the following lines to `~/.bashrc`:

```sh
#Go
export PATH="$PATH:/usr/lib/go-1.14/bin" #todo: use update-alternatives?
export GOPATH=$HOME/go
export GOBIN=$GOPATH/bin
export PATH=$PATH:$GOBIN
```

Then execute:
`source ~/.bashrc`

### Installation

```sh
git clone https://github.com/fantostisch/wireguard-daemon.git
cd wireguard-daemon
make
(cd deploy && sudo bash ./deploy.sh 51820)
make run
```

#### Set up NAT

Execute the following and replace `eth0` with your primary network interface which you can find by executing `sudo ifconfig`.
```sh
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
```

## Manage WireGuard

### Disable WireGuard
```sh
sudo ip link set down wg0
```

### Enable WireGuard
```sh
sudo ip link set up wg0
```
