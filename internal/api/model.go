package api

import (
	"net"

	"github.com/fantostisch/wireguard-daemon/pkg/wgmanager"
)

type PublicKey = wgmanager.PublicKey
type PrivateKey = wgmanager.PrivateKey

type UserID string

type UserConfig struct {
	IsDisabled bool                        `json:"isDisabled"`
	Clients    map[PublicKey]*ClientConfig `json:"clients"`
}

type ClientConfig struct {
	Name     string `json:"name"`
	IP       net.IP `json:"ip"`
	Modified TimeJ  `json:"modified"`
}
