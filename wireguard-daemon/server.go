package main

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"sync"

	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Server struct {
	serverConfPath string
	mutex          sync.RWMutex
	Config         *WgConf
	IPAddr         net.IP
	clientIPRange  *net.IPNet
	assets         http.Handler
}

type wgLink struct {
	attrs *netlink.LinkAttrs
}

func (w *wgLink) Attrs() *netlink.LinkAttrs {
	return w.attrs
}

func (w *wgLink) Type() string {
	return "wireguard"
}

func NewServer() *Server {
	ipAddr, ipNet, err := net.ParseCIDR("10.0.0.1/8")
	if err != nil {
		log.Fatal("Error with those IPS:", err)
	}
	log.Printf("IP Address: %s IP Network: %s", ipAddr, ipNet)
	err = os.Mkdir(*dataDir, 0700)
	if err != nil {
		log.Printf("Error creating directory: '%s'. Error message: %s", *dataDir, err)
	}
	configPath := path.Join(*dataDir, "conf.json")
	log.Print(configPath)
	config := newServerConfig(configPath)

	assets := http.FileServer(&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo, Prefix: ""})
	surf := Server{
		serverConfPath: configPath,
		mutex:          sync.RWMutex{},
		Config:         config,
		IPAddr:         ipAddr,
		clientIPRange:  ipNet,
		assets:         assets,
	}
	return &surf
}

func (serv *Server) Start() error {
	err := serv.UpInterface()
	if err != nil {
		return err
	}
	log.Print("------------------------------------------")
	log.Print("Enabling IP Forward....")
	err = serv.enableIPForward()
	if err != nil {
		log.Print("Couldnt enable IP Forwarding:  ", err)
		return err
	}
	err = serv.wgConfiguation()
	if err != nil {
		log.Print("Couldnt Configure interface ::", err)
		return err
	}
	return nil
}

func (serv *Server) UpInterface() error {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = *wgLinkName
	link := wgLink{attrs: &attrs}
	log.Print("------------------------------------------")
	log.Print("Adding WireGuard device ", attrs.Name)
	err := netlink.LinkAdd(&link)
	if os.IsExist(err) {
		log.Printf("WireGuard interface %s already exists. REUSING. ", attrs.Name)
	} else if err != nil {
		log.Print("Problem with the interface :::", err)
		return nil
	}
	log.Print("------------------------------------------")
	log.Print("Setting up IP address to wireguard device: ", serv.clientIPRange)
	addr, _ := netlink.ParseAddr("10.0.0.1/8")
	err = netlink.AddrAdd(&link, addr)
	if os.IsExist(err) {
		log.Printf("WireGuard interface %s already has the requested address: ", serv.clientIPRange)
	} else if err != nil {
		log.Print(err)
		return err
	}
	log.Print("------------------------------------------")
	log.Print("Bringing up wireguard device: ", attrs.Name)
	err = netlink.LinkSetUp(&link)

	if err != nil {
		log.Printf("Couldn't bring up %s", attrs.Name)
	}
	wgStatus = true
	return nil
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
	log.Fatal("Unable to allocate IP.Address range Exhausted")
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

func (serv *Server) wgConfiguation() error {
	log.Print("------------------------------------------")
	log.Print("Configuring WireGuard")
	wg, err := wgctrl.New()
	if err != nil {
		log.Print("There is an error configuring WireGuard ::", err)
	}
	log.Print("Adding PrivetKey....")
	keys, err := wgtypes.ParseKey(serv.Config.PrivateKey)
	if err != nil {
		log.Print("Couldn't add PrivateKey ::", err)
	}
	log.Print("PrivateKey->Successfully added -", serv.Config.PrivateKey)
	peers := make([]wgtypes.PeerConfig, 0)
	for user, cfg := range serv.Config.Users {
		for id, dev := range cfg.Clients {
			pbkey, err := wgtypes.ParseKey(dev.PublicKey)
			log.Print("PublicKey TO client - Added")
			if err != nil {
				log.Print("Couldn't add PublicKey to peer :: ", err)
			}
			AllowedIPs := make([]net.IPNet, 1)
			AllowedIPs[0] = *netlink.NewIPNet(dev.IP)
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
	//pers := time.Duration(21)
	//ip := net.ParseIP("10.0.0.2/8")
	//peer_key, err := wgtypes.ParseKey("hY6dXQboU1KRwUZ/UGFecIw6JKN97/RO6wQDkWA0MXA=")
	//wgAllowedIPs := make([]net.IPNet,1)
	//wgAllowedIPs[0] = *netlink.NewIPNet(ip)
	//peerA := wgtypes.PeerConfig{
	//	PublicKey:         peer_key,
	//	ReplaceAllowedIPs: false,
	//	PersistentKeepaliveInterval: &pers,
	//
	//}

	//peers = append(peers, peerA)
	//log.Print("successfuly added ME")
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
	log.Printf("Reconfiguring wireGuard interface: wg0")

	err := serv.Config.Write()
	if err != nil {
		log.Fatal("Error Writing on configuration file ", err)
		return err
	}
	err = serv.wgConfiguation()
	if err != nil {
		log.Printf("Error Configuring file :: %s", err)
		return err
	}
	return nil
}

func (serv *Server) Stop() error {
	log.Print("Turning down link ::: ")
	link, err := netlink.LinkByName(*wgLinkName)
	if err != nil {
		log.Print("error getting link ::: ", err)
	}

	err = netlink.LinkSetDown(link)
	if err != nil {
		log.Print("Error removing the interface ::: ", err)
		return err
	}
	log.Print("Interface shutdown")
	wgStatus = false

	return nil
}
