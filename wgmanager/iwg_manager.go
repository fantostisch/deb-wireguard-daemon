package wgmanager

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey  PublicKey
	AllowedIPs []net.IPNet
}

type IWGManager interface {
	GeneratePrivateKey() (PrivateKey, error)
	ConfigureWG(peers []Peer) error
	AddPeers(peers []Peer) error
	RemovePeers(publicKeys []PublicKey) error
	GetConnections() ([]wgtypes.Peer, error)
}
