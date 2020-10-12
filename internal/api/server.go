package api

import (
	"io/ioutil"
	"log"
	"net"
	"path"
	"sync"

	"github.com/fantostisch/wireguard-daemon/pkg/wgmanager"
)

type Server struct {
	wgInterface    string
	serverConfPath string
	mutex          sync.RWMutex
	Storage        *FileStorage
	IPAddr         net.IP
	clientIPRange  *net.IPNet
	wgManager      wgmanager.IWGManager
}

func NewServer(storage *FileStorage, wgManager wgmanager.IWGManager, wgInterface string) *Server {
	ipAddr, ipNet, err := net.ParseCIDR("10.0.0.1/8")
	if err != nil {
		log.Fatal("Error with IPS:", err)
	}
	log.Printf("IP Address: %s IP Network: %s", ipAddr, ipNet)

	configPath := path.Join(storage.filePath, "conf.json")
	log.Print(configPath)

	surf := Server{
		wgInterface:    wgInterface,
		serverConfPath: configPath,
		mutex:          sync.RWMutex{},
		Storage:        storage,
		IPAddr:         ipAddr,
		clientIPRange:  ipNet,
		wgManager:      wgManager,
	}
	return &surf
}

func (serv *Server) Start() error {
	log.Print("Enabling IP Forward....")
	err := serv.enableIPForwarding()
	if err != nil {
		log.Print("Couldn't enable IP Forwarding: ", err)
		return err
	}
	err = serv.configureWG()
	if err != nil {
		log.Print("Couldn't configure interface: ", err)
		return err
	}

	err = ExecScript("start.sh", serv.wgInterface)

	return err
}

func (serv *Server) allocateIP() net.IP {
	allocated := make(map[string]bool)
	allocated[serv.IPAddr.String()] = true

	for _, cfg := range serv.Storage.Data.Users {
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
			return ip
		}
	}
	log.Fatal("Unable to allocate IP Address, range exhausted")
	return nil
}

func (serv *Server) enableIPForwarding() error {
	p := "/proc/sys/net/ipv4/ip_forward"

	content, err := ioutil.ReadFile(p)
	if err != nil {
		return err
	}

	if string(content) == "0\n" {
		return ioutil.WriteFile(p, []byte("1"), 0600)
	}

	return nil
}

func (serv *Server) configureWG() error {
	var enabledUsers []UserConfig
	for _, user := range serv.Storage.Data.Users {
		if !user.IsDisabled {
			enabledUsers = append(enabledUsers, *user)
		}
	}

	var users []wgmanager.User
	for _, user := range enabledUsers {
		for publicKey, config := range user.Clients {
			users = append(users, wgmanager.User{
				PublicKey: publicKey,
				IP:        config.IP,
			})
		}
	}

	return serv.wgManager.ConfigureWG(serv.Storage.Data.PrivateKey, users)
}

func (serv *Server) reconfigureWG() error {
	err := serv.Storage.Write()
	if err != nil {
		log.Fatal("Error writing configuration file: ", err)
		return err
	}
	err = serv.configureWG()
	if err != nil {
		log.Printf("Error configuring file: %s", err)
		return err
	}
	return nil
}

func (serv *Server) Stop() error {
	err := ExecScript("stop.sh", serv.wgInterface)
	return err
}
