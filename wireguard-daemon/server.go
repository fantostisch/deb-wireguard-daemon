package main

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"sync"
)

type Server struct {
	serverConfPath string
	mutex          sync.RWMutex
	Config         *Configuration
	IPAddr         net.IP
	clientIPRange  *net.IPNet
	configureWG    func(s *Server) error
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
		configureWG:    configureWG,
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
	err = serv.configureWG(serv)
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

func (serv *Server) reconfigureWG() error {
	err := serv.Config.Write()
	if err != nil {
		log.Fatal("Error writing configuration file: ", err)
		return err
	}
	err = serv.configureWG(serv)
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
