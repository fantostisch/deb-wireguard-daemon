# WireGuard Daemon

#### It is not ready yet! The configuration of the DNS’s, Authentication etc are not implemented.

## Setup

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

### Installation on Debian
When using Debian Buster, Wireguard and Go need to be installed from backports, which needs to be enabled. [Instructions for enabling backports on Debian](https://backports.debian.org/Instructions/).

```sh
sudo apt-get -y install linux-headers-amd64 #todo: architecture independent command
sudo apt-get -y -t buster-backports install golang-1.14-go #or: sudo apt-get -y install golang-1.14-go
go version # Test if go is successfully installed.
sudo apt-get -y -t buster-backports install wireguard #or: sudo apt-get install wireguard
wg version # Test if WireGuard is successfully installed.
git clone https://gitlab.com/fantostisch/wireguard-daemon.git
cd wireguard-daemon
go get # Install dependencies
make
```

### Set up NAT

Execute the following and replace `eth0` with your primary network interface which you can find by executing `sudo ifconfig`.
```sh
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
```

### Running

Make sure UDP port 51820 is open.

`make run`

To stop the wireguard-daemon press Ctrl+c.

## Using the VPN:

[Download WireGuard](https://www.wireguard.com/install/) for your device, create an account in the vpn-user-portal and import the config by either downloading it or scanning the QR Code.

### Manual setup

To generate a public and public-private key pair run:
`wg genkey | tee privatekey | wg pubkey > publickey`

##### Manually adding a user

To manually add a user modify conf.json. For an example take a look at [conf.example.json](wireguard-daemon/conf.example.json).

#### Manually creating a config

Copy the following into a file ending in `.conf`, fill in your private key, the public key of the server and the server url, then import it into your WireGuard client.

```
[Interface]
PrivateKey = <client private key>
Address = 10.0.0.2/32
DNS = 8.8.8.8
[Peer]
PublicKey = <server public key>
AllowedIPs = 0.0.0.0/0
Endpoint = <server ip>:51820
```
 
## API endpoints
|Method|Url|Data|Description
|----|---|---|---|
|GET|/identify| ||
|GET|/WG/API/{user}/clients|| List all of the clients of the user.|
GET|/WG/API/{user}/clients/{client id}|| Show the first client of the user.|
POST|/WG/API/{user}/clients |{"Name": "Some_name", "Info": "Some_info"}| Create client config with some name and some info. For now it generates both the private key and the public and it assignes an IP.|
|PUT| /WG/API/{user}/clients/{client id}|{"Name": "Some_name", "Info": "Some_info"}|Updates client config with some_name and some info.|
DELETE|/WG/API/{user}/clients/{client number}|| Delete a user.|

todo: document how to get QR code
