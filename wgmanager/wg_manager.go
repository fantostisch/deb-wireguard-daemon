package wgmanager

import (
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WGManager struct {
	WGInterface string
	client      *wgctrl.Client
}

func New(wgInterface string) (*WGManager, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &WGManager{
		WGInterface: wgInterface,
		client:      wgClient,
	}, nil
}

func (wgm WGManager) GetPublicKey() (PublicKey, error) {
	wgDevice, err := wgm.client.Device(wgm.WGInterface)
	if wgDevice == nil || err != nil {
		return PublicKey{}, err
	}
	return PublicKey{wgDevice.PublicKey}, nil
}

func (wgm WGManager) GeneratePrivateKey() (PrivateKey, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	return PrivateKey{privateKey}, err
}

func (wgm WGManager) ConfigureWG(peers []Peer) error {
	wgPeers := []wgtypes.PeerConfig{}

	for _, peer := range peers {
		wgPeer := wgtypes.PeerConfig{
			PublicKey:         peer.PublicKey.Key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        peer.AllowedIPs,
		}
		wgPeers = append(wgPeers, wgPeer)
	}

	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers:        wgPeers,
	}
	err := wgm.client.ConfigureDevice(wgm.WGInterface, cfg)
	if err != nil {
		return fmt.Errorf("error configuring WireGuard device: %w", err)
	}
	return nil
}

func (wgm WGManager) AddPeers(peers []Peer) error {
	wgPeers := []wgtypes.PeerConfig{}

	for _, peer := range peers {
		wgPeers = append(wgPeers, wgtypes.PeerConfig{
			Remove:            false,
			UpdateOnly:        false,
			PublicKey:         peer.PublicKey.Key,
			ReplaceAllowedIPs: true,
			AllowedIPs:        peer.AllowedIPs,
		})
	}

	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        wgPeers,
	}
	err := wgm.client.ConfigureDevice(wgm.WGInterface, cfg)
	if err != nil {
		return fmt.Errorf("error adding peer to WireGuard: %w", err)
	}
	return nil
}

func (wgm WGManager) RemovePeers(publicKeys []PublicKey) error {
	wgPeers := []wgtypes.PeerConfig{}

	for _, publicKey := range publicKeys {
		wgPeers = append(wgPeers, wgtypes.PeerConfig{
			PublicKey: publicKey.Key,
			Remove:    true,
		})
	}

	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        wgPeers,
	}
	err := wgm.client.ConfigureDevice(wgm.WGInterface, cfg)
	if err != nil {
		return fmt.Errorf("error removing peers from WireGuard: %w", err)
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
