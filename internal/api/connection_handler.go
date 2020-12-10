package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fantostisch/wireguard-daemon/wgmanager"
)

type ConnectionHandler struct {
	wgManager wgmanager.IWGManager
	storage   *FileStorage
}

type Connection struct {
	PublicKey  PublicKey `json:"publicKey"`
	AllowedIPs []string  `json:"allowedIPs"`
}

func (h ConnectionHandler) getConnections(w http.ResponseWriter) {
	peers, err := h.wgManager.GetConnections()
	if peers == nil || err != nil {
		message := fmt.Sprintf("Error getting WireGuard connections: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	response := map[UserID]*[]Connection{}

	for _, peer := range peers {
		publicKey := PublicKey{peer.PublicKey}
		username, _, err := h.storage.GetUsernameAndConfig(publicKey)
		if err != nil {
			message := fmt.Sprintf("Error no user found for public key: %s", publicKey)
			http.Error(w, message, http.StatusInternalServerError)
			return
		}
		userPeerList := response[username]
		if userPeerList == nil {
			userPeerList = &[]Connection{}
			response[username] = userPeerList
		}
		var allowedIPsString []string
		for _, IP := range peer.AllowedIPs {
			allowedIPsString = append(allowedIPsString, IP.String())
		}
		*userPeerList = append(*userPeerList, Connection{
			PublicKey:  publicKey,
			AllowedIPs: allowedIPsString,
		})
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}
