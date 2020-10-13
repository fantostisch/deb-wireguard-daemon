package wgmanager

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type User struct {
	PublicKey string
	IP        net.IP
}

type IWGManager interface {
	ConfigureWG(privateKey string, users []User) error
	GetConnections() ([]wgtypes.Peer, error)
}
