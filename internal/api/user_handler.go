package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/fantostisch/wireguard-daemon/wgmanager"
)

type UserHandler struct {
	Server *Server
}

// Get all configs of a user.
func (h UserHandler) getConfigs(w http.ResponseWriter, username UserID) {
	clients := h.Server.Storage.GetUserClients(username)

	if err := json.NewEncoder(w).Encode(clients); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}

type createConfigAndKeyPairResponse struct {
	ClientPrivateKey PrivateKey `json:"clientPrivateKey"`
	ClientPublicKey  PublicKey  `json:"clientPublicKey"`
	IP               net.IP     `json:"ip"`
	ServerPublicKey  PublicKey  `json:"serverPublicKey"`
}

type createConfigResponse struct {
	IP              net.IP    `json:"ip"`
	ServerPublicKey PublicKey `json:"serverPublicKey"`
}

func (h UserHandler) newConfig(username UserID, publicKey PublicKey) (createConfigResponse, error) {
	var config ClientConfig

	for {
		ip, err := h.Server.allocateIP()
		if ip == nil || err != nil {
			return createConfigResponse{}, fmt.Errorf("error getting IP Address: %w", err)
		}
		config = NewClientConfig(ip)
		success, err := h.Server.Storage.UpdateOrCreateConfig(username, publicKey, config)
		if err != nil {
			return createConfigResponse{}, fmt.Errorf("error saving config: %w", err)
		}
		if err := h.Server.wgManager.AddPeers([]wgmanager.Peer{ClientToWGPeer(publicKey, config)}); err != nil {
			return createConfigResponse{}, fmt.Errorf("error adding peer to WireGuard: %w", err)
		}
		if success {
			break
		}
	}

	return createConfigResponse{
		IP:              config.IP,
		ServerPublicKey: h.Server.GetPublicKey(),
	}, nil
}

func (h UserHandler) createConfigGenerateKeyPair(w http.ResponseWriter, username UserID) {
	clientPrivateKey, err := h.Server.wgManager.GeneratePrivateKey()
	if err != nil {
		message := fmt.Sprintf("Error generating private key: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	clientPublicKey := clientPrivateKey.PublicKey()
	createConfigResponse, err := h.newConfig(username, clientPublicKey)
	if err != nil {
		message := fmt.Sprintf("Error creating config: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	response := createConfigAndKeyPairResponse{
		ClientPrivateKey: clientPrivateKey,
		ClientPublicKey:  clientPublicKey,
		IP:               createConfigResponse.IP,
		ServerPublicKey:  createConfigResponse.ServerPublicKey,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}

func (h UserHandler) createConfig(w http.ResponseWriter, username UserID, publicKey PublicKey) {
	response, err := h.newConfig(username, publicKey)
	if err != nil {
		message := fmt.Sprintf("Error creating config: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}

func (h UserHandler) deleteConfig(w http.ResponseWriter, username UserID, publicKey PublicKey) {
	deleted, err := h.Server.Storage.DeleteConfig(username, publicKey)
	if err != nil {
		message := fmt.Sprintf("Error deleting config: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	if !deleted {
		message := fmt.Sprintf(
			"Config not found: User '%s' does not have a config with public key '%s'", username, publicKey.String())
		replyWithError(w, ConfigNotFound, message)
		return
	}

	if err := h.Server.wgManager.RemovePeers([]PublicKey{publicKey}); err != nil {
		message := fmt.Sprintf("Error removing peer from WireGuard: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h UserHandler) setDisabledHTTP(w http.ResponseWriter, username UserID, disabled bool,
	apiError Error, conflictMessage string) {

	valueChanged, err := h.Server.Storage.SetDisabled(username, disabled)
	if err != nil {
		message := fmt.Sprintf("Error enabling/disabling user: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	if !valueChanged {
		replyWithError(w, apiError, conflictMessage)
		return
	}

	clients := h.Server.Storage.GetUserClients(username)
	if disabled {
		var publicKeys []PublicKey
		for publicKey := range clients {
			publicKeys = append(publicKeys, publicKey)
		}
		err = h.Server.wgManager.RemovePeers(publicKeys)
	} else {
		var wgPeers []wgmanager.Peer
		for publicKey, config := range clients {
			wgPeers = append(wgPeers, ClientToWGPeer(publicKey, config))
		}
		err = h.Server.wgManager.AddPeers(wgPeers)
	}
	if err != nil {
		message := fmt.Sprintf("Error reconfiguring WireGuard: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

//todo: disabling a user does not free its ip addresses, a malicious user can claim all ip addresses
func (h UserHandler) disableUser(w http.ResponseWriter, username UserID) {
	h.setDisabledHTTP(w, username, true, UserAlreadyDisabled, fmt.Sprintf("User %s was already disabled.", username))
}

func (h UserHandler) enableUser(w http.ResponseWriter, username UserID) {
	h.setDisabledHTTP(w, username, false, UserAlreadyEnabled, fmt.Sprintf("User %s was already enabled.", username))
}
