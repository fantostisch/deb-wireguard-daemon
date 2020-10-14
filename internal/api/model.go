package api

import (
	"net"
	"time"

	"github.com/fantostisch/wireguard-daemon/wgmanager"
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

func ClientToWGPeer(publicKey PublicKey, client ClientConfig) wgmanager.Peer {
	allowedIPs := make([]net.IPNet, 1)
	amountOfBitsInIPv4Address := 32
	allowedIPs[0] = net.IPNet{
		IP:   client.IP,
		Mask: net.CIDRMask(amountOfBitsInIPv4Address, amountOfBitsInIPv4Address),
	}
	return wgmanager.Peer{
		PublicKey:  publicKey,
		AllowedIPs: allowedIPs,
	}
}
