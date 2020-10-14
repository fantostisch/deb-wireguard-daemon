package api

import (
	"net"
	"time"

	"github.com/fantostisch/wireguard-daemon/pkg/wgmanager"
)

type PublicKey = wgmanager.PublicKey
type PrivateKey = wgmanager.PrivateKey

type UserID string

type User struct {
	IsDisabled bool                       `json:"isDisabled"`
	Clients    map[PublicKey]ClientConfig `json:"clients"`
}

type ClientConfig struct {
	Name     string `json:"name"`
	IP       net.IP `json:"ip"`
	Modified TimeJ  `json:"modified"`
}

func NewClientConfig(name string, ip net.IP) ClientConfig {
	now := TimeJ{time.Now().UTC()}
	config := ClientConfig{
		Name:     name,
		IP:       ip,
		Modified: now,
	}
	return config
}
