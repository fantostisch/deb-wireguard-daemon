package wgmanager

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type User struct {
	PublicKey PublicKey
	IP        net.IP
}

type IWGManager interface {
	GeneratePrivateKey() (PrivateKey, error)
	ConfigureWG(privateKey PrivateKey, users []User) error
	GetConnections() ([]wgtypes.Peer, error)
}
