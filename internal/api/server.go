package api

import (
	"errors"
	"log"
	"net"
	"net/http"

	"github.com/fantostisch/wireguard-daemon/wgmanager"
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

func (s *Server) Start(listenAddress string) error {
	err := s.configureWG()
	if err != nil {
		return err
	}

	var router http.Handler = API{
		UserHandler:       UserHandler{Server: s},
		ConnectionHandler: ConnectionHandler{wgManager: s.wgManager, storage: s.Storage},
	}
	return http.ListenAndServe(listenAddress, router)
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

func (s *Server) configureWG() error {
	enabledUsers := s.Storage.GetEnabledUsers()

	var wgPeers []wgmanager.Peer
	for _, user := range enabledUsers {
		for publicKey, config := range user.Clients {
			wgPeers = append(wgPeers, ClientToWGPeer(publicKey, config))
		}
	}

	return s.wgManager.ConfigureWG(wgPeers)
}
