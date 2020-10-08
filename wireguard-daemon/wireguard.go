package main

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type ParsePublicKeyErrorList struct {
	errors []ParsePublicKeyError
}

func (e ParsePublicKeyErrorList) Error() string {
	return fmt.Sprintf("could not parse public keys: %v", e.errors)
}

type ParsePublicKeyError struct {
	publicKey string
	err       error
}

func (e ParsePublicKeyError) Error() string {
	return fmt.Sprintf("could not parse public keys: %s", e.publicKey)
}

func (e ParsePublicKeyError) Unwrap() error {
	return e.err
}

//todo: do not reconfigure everything when only adding or deleting one config
func configureWG(serv *Server) error {
	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creating WireGuard client: %w", err)
	}
	keys, err := wgtypes.ParseKey(serv.Config.PrivateKey)
	if err != nil {
		return fmt.Errorf("could not parse server private key: %w", err)
	}
	peers := make([]wgtypes.PeerConfig, 0)

	enabledUsers := Filter(serv.Config.Users, func(k Key, v Value) bool { return !v.IsDisabled })

	var parsePublicKeyErrors []ParsePublicKeyError

	for _, cfg := range enabledUsers {
		for publicKey, dev := range cfg.Clients {
			pbkey, err := wgtypes.ParseKey(publicKey)
			if err != nil {
				parsePublicKeyErrors = append(parsePublicKeyErrors, ParsePublicKeyError{
					publicKey: publicKey,
					err:       err,
				})
			} else {
				AllowedIPs := make([]net.IPNet, 1)
				amountOfBitsInIPv4Address := 32
				AllowedIPs[0] = net.IPNet{
					IP:   dev.IP,
					Mask: net.CIDRMask(amountOfBitsInIPv4Address, amountOfBitsInIPv4Address),
				}
				peer := wgtypes.PeerConfig{
					PublicKey:         pbkey,
					ReplaceAllowedIPs: true,
					AllowedIPs:        AllowedIPs,
				}
				peers = append(peers, peer)
			}
		}
	}

	cfg := wgtypes.Config{
		PrivateKey:   &keys,
		ListenPort:   &wgPort,
		ReplacePeers: true,
		Peers:        peers,
	}
	err = wg.ConfigureDevice("wg0", cfg)
	if err != nil {
		return fmt.Errorf("error configuring WireGuard device: %w", err)
	}
	if len(parsePublicKeyErrors) > 0 {
		return ParsePublicKeyErrorList{errors: parsePublicKeyErrors}
	}
	return nil
}
