package api

import (
	"errors"
	"io/ioutil"
	"log"
	"net"

	"github.com/fantostisch/wireguard-daemon/pkg/wgmanager"
)

type Server struct {
	wgInterface   string
	Storage       *FileStorage
	IPAddr        net.IP
	clientIPRange *net.IPNet
	wgManager     wgmanager.IWGManager
}

func NewServer(storage *FileStorage, wgManager wgmanager.IWGManager, wgInterface string) *Server {
	IPAddr, ipNet, err := net.ParseCIDR("10.0.0.1/8")
	if err != nil {
		log.Fatal("Error with IPs:", err)
	}

	surf := Server{
		wgInterface:   wgInterface,
		Storage:       storage,
		IPAddr:        IPAddr,
		clientIPRange: ipNet,
		wgManager:     wgManager,
	}
	return &surf
}

func (s *Server) Start() error {
	log.Print("Enabling IP Forward....")
	err := s.enableIPForwarding()
	if err != nil {
		return err
	}
	err = s.configureWG()
	if err != nil {
		return err
	}

	err = ExecScript("start.sh", s.wgInterface)

	return err
}

func (s *Server) allocateIP() (net.IP, error) {
	allocatedIPs := s.Storage.GetAllocatedIPs()
	allocatedIPs = append(allocatedIPs, s.IPAddr)

	for ip := s.IPAddr.Mask(s.clientIPRange.Mask); s.clientIPRange.Contains(ip); {
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] > 0 {
				break
			}
		}
		allocated := false
		for _, allocatedIP := range allocatedIPs {
			if allocatedIP.Equal(ip) {
				allocated = true
				break
			}
		}
		if !allocated {
			return ip, nil
		}
	}
	return nil, errors.New("unable to allocate IP Address, range exhausted")
}

func (s *Server) enableIPForwarding() error {
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

func (s *Server) configureWG() error {
	enabledUsers := s.Storage.GetEnabledUsers()

	var users []wgmanager.Peer
	for _, user := range enabledUsers {
		for publicKey, config := range user.Clients {
			allowedIPs := make([]net.IPNet, 1)
			amountOfBitsInIPv4Address := 32
			allowedIPs[0] = net.IPNet{
				IP:   config.IP,
				Mask: net.CIDRMask(amountOfBitsInIPv4Address, amountOfBitsInIPv4Address),
			}

			users = append(users, wgmanager.Peer{
				PublicKey:  publicKey,
				AllowedIPs: allowedIPs,
			})
		}
	}

	return s.wgManager.ConfigureWG(s.Storage.GetServerPrivateKey(), users)
}

func (s *Server) Stop() error {
	err := ExecScript("stop.sh", s.wgInterface)
	return err
}
