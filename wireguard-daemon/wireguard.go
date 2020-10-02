package main

import (
	"log"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

//todo: do not reconfigure everything when only adding or deleting one config
func configureWG(serv *Server) error {
	wg, err := wgctrl.New()
	if err != nil {
		log.Print("Error configuring WireGuard: ", err)
	}
	keys, err := wgtypes.ParseKey(serv.Config.PrivateKey)
	if err != nil {
		log.Print("Couldn't add private key: ", err)
	}
	peers := make([]wgtypes.PeerConfig, 0)
	for _, cfg := range serv.Config.Users {
		for publicKey, dev := range cfg.Clients {
			pbkey, err := wgtypes.ParseKey(publicKey)
			if err != nil {
				log.Print("Couldn't add public key to peer: ", err) //todo: return error
			}
			AllowedIPs := make([]net.IPNet, 1)
			amountOfBitsInIPv4Address := 32
			AllowedIPs[0] = net.IPNet{IP: dev.IP, Mask: net.CIDRMask(amountOfBitsInIPv4Address, amountOfBitsInIPv4Address)}
			peer := wgtypes.PeerConfig{
				PublicKey:         pbkey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        AllowedIPs,
			}
			peers = append(peers, peer)
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
		log.Fatal("Error configuring device: ", err)
		return err
	}
	return nil
}
