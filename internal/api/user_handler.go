package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/fantostisch/wireguard-daemon/wgmanager"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	IP               net.IP     `json:"ip"`
	ServerPublicKey  PublicKey  `json:"serverPublicKey"`
}

type createConfigResponse struct {
	IP              net.IP    `json:"ip"`
	ServerPublicKey PublicKey `json:"serverPublicKey"`
}

func (h UserHandler) newConfig(username UserID, publicKey PublicKey, name string) (createConfigResponse, error) {
	var config ClientConfig

	for {
		ip, err := h.Server.allocateIP()
		if ip == nil || err != nil {
			return createConfigResponse{}, fmt.Errorf("error getting IP Address: %w", err)
		}
		config = NewClientConfig(name, ip)
		success, err := h.Server.Storage.UpdateOrCreateConfig(username, publicKey, config)
		if err != nil {
			return createConfigResponse{}, fmt.Errorf("error saving config: %w", err)
		}
		if err := h.Server.wgManager.AddPeers([]wgmanager.Peer{ClientToWGPeer(publicKey, config)}); err != nil {
			return createConfigResponse{}, fmt.Errorf("error config peer to WireGuard: %w", err)
		}
		if success {
			break
		}
	}

	return createConfigResponse{
		IP:              config.IP,
		ServerPublicKey: h.Server.Storage.GetServerPublicKey(),
	}, nil
}

// reconfigureWGHTTP reconfigures WireGuard. If there is an error it responds
// a InternalServerError and returns false. If it succeeds no response is
// written and true is returned.
func (h UserHandler) reconfigureWGHTTP(w http.ResponseWriter) bool {
	if err := h.Server.configureWG(); err != nil {
		message := fmt.Sprintf("Error reconfiguring WireGuard: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return false
	}
	return true
}

func (h UserHandler) createConfigGenerateKeyPair(w http.ResponseWriter, username UserID, name string) {
	clientPrivateKey, err := h.Server.wgManager.GeneratePrivateKey()
	if err != nil {
		message := fmt.Sprintf("Error generating private key: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	clientPublicKey := clientPrivateKey.PublicKey()
	createConfigResponse, err := h.newConfig(username, clientPublicKey, name)
	if err != nil {
		message := fmt.Sprintf("Error creating config: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	response := createConfigAndKeyPairResponse{
		ClientPrivateKey: clientPrivateKey,
		IP:               createConfigResponse.IP,
		ServerPublicKey:  createConfigResponse.ServerPublicKey,
	}

	if !h.reconfigureWGHTTP(w) {
		return
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}

func (h UserHandler) createConfig(w http.ResponseWriter, username UserID, publicKey PublicKey, name string) {
	response, err := h.newConfig(username, publicKey, name)
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
	w.WriteHeader(http.StatusOK)
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
		http.Error(w, message, http.StatusConflict)
		return
	}

	if !h.reconfigureWGHTTP(w) {
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h UserHandler) setDisabledHTTP(w http.ResponseWriter, username UserID, disabled bool, conflictMessage string) {
	valueChanged, err := h.Server.Storage.SetDisabled(username, disabled)
	if err != nil {
		message := fmt.Sprintf("Error enabling/disabling user: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	if !valueChanged {
		http.Error(w, conflictMessage, http.StatusConflict)
	}

	clients := h.Server.Storage.GetUserClients(username)
	var wgPeers []wgmanager.Peer
	for publicKey, config := range clients {
		wgPeers = append(wgPeers, ClientToWGPeer(publicKey, config))
	}

	if disabled {
		err = h.Server.configureWG()
	} else {
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
	h.setDisabledHTTP(w, username, true, fmt.Sprintf("User %s was already disabled.", username))
}

func (h UserHandler) enableUser(w http.ResponseWriter, username UserID) {
	h.setDisabledHTTP(w, username, false, fmt.Sprintf("User %s was already enabled.", username))
}

// getRequiredValue gets a value from the HTTP parameters. If the value is not available an error response will be
// written and an empty string will be returned.
// Assumption: req.Form was was populated by calling req.ParseForm()
func (h UserHandler) getRequiredValue(w http.ResponseWriter, req *http.Request, key string) string {
	value := req.Form.Get(key)
	if value == "" {
		contentType := req.Header.Get("Content-Type")
		const form = "application/x-www-form-urlencoded"
		if contentType != form {
			message := fmt.Sprintf("Content-Type '%s' was not equal to %s'", contentType, form)
			http.Error(w, message, http.StatusUnsupportedMediaType)
			return ""
		}
		http.Error(w, "%s was not supplied.", http.StatusBadRequest)
		return ""
	}
	return value
}

func (h UserHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, url string, username UserID) {
	firstSegment, _ := ShiftPath(url)
	switch firstSegment {
	case "config":
		receivedPublicKey := req.Form.Get("public_key")
		if receivedPublicKey == "" {
			switch req.Method {
			case http.MethodGet:
				h.getConfigs(w, username)
			case http.MethodPost:
				name := h.getRequiredValue(w, req, "name")
				if name == "" {
					return
				}
				h.createConfigGenerateKeyPair(w, username, name)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
		} else {
			publicKey, err := wgtypes.ParseKey(receivedPublicKey)
			if err != nil {
				message := fmt.Sprintf("Invalid public key: '%s'. %s", receivedPublicKey, err)
				http.Error(w, message, http.StatusBadRequest)
				return
			}
			switch req.Method {
			case http.MethodPost:
				name := h.getRequiredValue(w, req, "name")
				if name == "" {
					return
				}
				h.createConfig(w, username, PublicKey{publicKey}, name)
			case http.MethodDelete:
				h.deleteConfig(w, username, PublicKey{publicKey})
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		}
	case "disable_user":
		h.disableUser(w, username)
	case "enable_user":
		h.enableUser(w, username)
	default:
		http.NotFound(w, req)
	}
}
