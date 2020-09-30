package main

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Server struct {
	serverConfPath string
	mutex          sync.RWMutex
	Config         *WgConf
	IPAddr         net.IP
	clientIPRange  *net.IPNet
}

func NewServer() *Server {
	ipAddr, ipNet, err := net.ParseCIDR("10.0.0.1/8")
	if err != nil {
		log.Fatal("Error with IPS:", err)
	}
	log.Printf("IP Address: %s IP Network: %s", ipAddr, ipNet)
	err = os.Mkdir(*dataDir, 0700)
	if err != nil {
		log.Printf("Error creating directory: '%s'. Error message: %s", *dataDir, err)
	}
	configPath := path.Join(*dataDir, "conf.json")
	log.Print(configPath)
	config := newServerConfig(configPath)

	surf := Server{
		serverConfPath: configPath,
		mutex:          sync.RWMutex{},
		Config:         config,
		IPAddr:         ipAddr,
		clientIPRange:  ipNet,
	}
	return &surf
}

func (serv *Server) Start() error {
	log.Print("Enabling IP Forward....")
	err := serv.enableIPForward()
	if err != nil {
		log.Print("Couldn't enable IP Forwarding: ", err)
		return err
	}
	err = serv.wgConfiguration()
	if err != nil {
		log.Print("Couldn't configure interface: ", err)
		return err
	}

	err = ExecScript("start.sh")

	return err
}

func (serv *Server) allocateIP() net.IP {
	allocated := make(map[string]bool)
	allocated[serv.IPAddr.String()] = true

	for _, cfg := range serv.Config.Users {
		for _, dev := range cfg.Clients {
			allocated[dev.IP.String()] = true
		}
	}

	for ip := serv.IPAddr.Mask(serv.clientIPRange.Mask); serv.clientIPRange.Contains(ip); {
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] > 0 {
				break
			}
		}
		if !allocated[ip.String()] {
			log.Print("Allocated IP: ", ip)
			return ip
		}
	}
	log.Fatal("Unable to allocate IP Address, range exhausted")
	return nil
}

func (serv *Server) enableIPForward() error {
	p := "/proc/sys/net/ipv4/ip_forward"

	content, err := ioutil.ReadFile(p)
	if err != nil {
		return err
	}

	if string(content) == "0\n" {
		log.Print("Enabling sys.net.ipv4.ip_forward - Success")
		return ioutil.WriteFile(p, []byte("1"), 0600)
	}

	return nil
}

func (serv *Server) wgConfiguration() error {
	log.Print("Configuring WireGuard")
	wg, err := wgctrl.New()
	if err != nil {
		log.Print("Error configuring WireGuard: ", err)
	}
	log.Print("Adding private key")
	keys, err := wgtypes.ParseKey(serv.Config.PrivateKey)
	if err != nil {
		log.Print("Couldn't add private key: ", err)
	}
	log.Print("Private key successfully added -", serv.Config.PrivateKey)
	peers := make([]wgtypes.PeerConfig, 0)
	for user, cfg := range serv.Config.Users {
		for id, dev := range cfg.Clients {
			pbkey, err := wgtypes.ParseKey(dev.PublicKey)
			log.Print("Public key to client - Added")
			if err != nil {
				log.Print("Couldn't add public key to peer: ", err)
			}
			AllowedIPs := make([]net.IPNet, 1)
			amountOfBitsInIPv4Address := 32
			AllowedIPs[0] = net.IPNet{IP: dev.IP, Mask: net.CIDRMask(amountOfBitsInIPv4Address, amountOfBitsInIPv4Address)}
			peer := wgtypes.PeerConfig{
				PublicKey:         pbkey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        AllowedIPs,
			}
			log.Printf("Adding user ")
			log.Printf("User: %s, ClientID %s: , Publickey: %s AllowedIPS: %s", user, id, dev.PublicKey, peer.AllowedIPs)
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
		log.Fatal("Error configuring device ::", err)
		return err
	}
	return nil
}

func (serv *Server) reconfiguringWG() error {
	log.Printf("Reconfiguring WireGuard interface: wg0")

	err := serv.Config.Write()
	if err != nil {
		log.Fatal("Error writing configuration file: ", err)
		return err
	}
	err = serv.wgConfiguration()
	if err != nil {
		log.Printf("Error configuring file: %s", err)
		return err
	}
	return nil
}

func (serv *Server) Stop() error {
	err := ExecScript("stop.sh")
	return err
}
