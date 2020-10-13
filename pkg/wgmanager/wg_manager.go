package wgmanager

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WGManager struct {
	WGPort      int
	WGInterface string
	client      *wgctrl.Client
}

func New(wgInterface string, wgPort int) (*WGManager, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &WGManager{
		WGPort:      wgPort,
		WGInterface: wgInterface,
		client:      wgClient,
	}, nil
}

func (wgm WGManager) ConfigureWG(privateKey string, users []User) error {
	keys, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("could not parse server private key: %w", err)
	}
	peers := make([]wgtypes.PeerConfig, 0)

	var parsePublicKeyErrors []ParsePublicKeyError

	for _, user := range users {
		publicKey, err := wgtypes.ParseKey(user.PublicKey)
		if err != nil {
			parsePublicKeyErrors = append(parsePublicKeyErrors, ParsePublicKeyError{
				publicKey: user.PublicKey,
				err:       err,
			})
		} else {
			AllowedIPs := make([]net.IPNet, 1)
			amountOfBitsInIPv4Address := 32
			AllowedIPs[0] = net.IPNet{
				IP:   user.IP,
				Mask: net.CIDRMask(amountOfBitsInIPv4Address, amountOfBitsInIPv4Address),
			}
			peer := wgtypes.PeerConfig{
				PublicKey:         publicKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        AllowedIPs,
			}
			peers = append(peers, peer)
		}
	}

	cfg := wgtypes.Config{
		PrivateKey:   &keys,
		ListenPort:   &wgm.WGPort,
		ReplacePeers: true,
		Peers:        peers,
	}
	err = wgm.client.ConfigureDevice(wgm.WGInterface, cfg)
	if err != nil {
		return fmt.Errorf("error configuring WireGuard device: %w", err)
	}
	if len(parsePublicKeyErrors) > 0 {
		return ParsePublicKeyErrorList{errors: parsePublicKeyErrors}
	}
	return nil
}

// GetConnections lists a config as connected when a handshake has been
// performed with the client in the last 3 minutes. If a WireGuard client
// did not perform a handshake in the last 3 minutes, all packets will be
// dropped by WireGuard until the client performs a new handshake.
func (wgm WGManager) GetConnections() ([]wgtypes.Peer, error) {
	wgDevice, err := wgm.client.Device(wgm.WGInterface)
	if wgDevice == nil || err != nil {
		return nil, err
	}

	peers := []wgtypes.Peer{}

	// nolint
	// Taken from https://git.kernel.org/pub/scm/linux/kernel/git/zx2c4/wireguard-linux.git/tree/drivers/net/wireguard/messages.h?id=805c6d3c19210c90c109107d189744e960eae025#n46
	const REJECT_AFTER_TIME = 180 * time.Second

	for _, p := range wgDevice.Peers {
		now := time.Now()
		if now.Sub(p.LastHandshakeTime) < REJECT_AFTER_TIME {
			peers = append(peers, p)
		}
	}
	return peers, nil
}

func (wgm WGManager) Close() error {
	return wgm.client.Close()
}
