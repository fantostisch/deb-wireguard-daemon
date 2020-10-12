package wgmanager

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WGManager struct {
	WGInterface string
	WGPort      int
}

func (wm WGManager) ConfigureWG(privateKey string, users []User) error {
	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating WireGuard client: %w", err)
	}
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
		ListenPort:   &wm.WGPort,
		ReplacePeers: true,
		Peers:        peers,
	}
	err = wg.ConfigureDevice(wm.WGInterface, cfg)
	if err != nil {
		return fmt.Errorf("error configuring WireGuard device: %w", err)
	}
	if len(parsePublicKeyErrors) > 0 {
		return ParsePublicKeyErrorList{errors: parsePublicKeyErrors}
	}
	return nil
}
