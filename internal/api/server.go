package api

import (
	"errors"
	"fmt"
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
	wgPublicKey   PublicKey
}

func NewServer(storage *FileStorage, wgManager wgmanager.IWGManager, wgInterface string) (*Server, error) {
	IPAddr, ipNet, err := net.ParseCIDR("10.0.0.1/8")
	if err != nil {
		return nil, fmt.Errorf("error parsing CIDR notation: %w", err)
	}

	wgPublicKey, err := wgManager.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting public key from WireGuard: %w", err)
	}

	surf := Server{
		wgInterface:   wgInterface,
		Storage:       storage,
		IPAddr:        IPAddr,
		clientIPRange: ipNet,
		wgManager:     wgManager,
		wgPublicKey:   wgPublicKey,
	}
	return &surf, nil
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

func (s *Server) GetPublicKey() PublicKey {
	return s.wgPublicKey
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
