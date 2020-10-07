package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type UserHandler struct {
	Server *Server
}

// Get all configs of a user.
func (h UserHandler) getConfigs(w http.ResponseWriter, username string) {
	clients := map[string]*ClientConfig{}

	h.Server.mutex.Lock()
	defer h.Server.mutex.Unlock()

	userConfig := h.Server.Config.Users[username]
	if userConfig != nil {
		clients = userConfig.Clients
	}

	if err := json.NewEncoder(w).Encode(clients); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}

type createConfigAndKeyPairResponse struct {
	ClientPrivateKey string `json:"clientPrivateKey"`
	IP               net.IP `json:"ip"`
	ServerPublicKey  string `json:"serverPublicKey"`
}

type createConfigResponse struct {
	IP              net.IP `json:"ip"`
	ServerPublicKey string `json:"serverPublicKey"`
}

func (h UserHandler) newConfig(username string, publicKey string, name string) createConfigResponse {
	h.Server.mutex.Lock()
	defer h.Server.mutex.Unlock()

	userConfig := h.Server.Config.GetUserConfig(username)

	ip := h.Server.allocateIP()
	config := NewClientConfig(name, ip)

	userConfig.Clients[publicKey] = &config

	return createConfigResponse{
		IP:              config.IP,
		ServerPublicKey: h.Server.Config.PublicKey,
	}
}

// reconfigureWGHTTP reconfigures WireGuard. If there is an error it responds
// a InternalServerError and returns false. If it succeeds no response is
// written and true is returned.
func (h UserHandler) reconfigureWGHTTP(w http.ResponseWriter) bool {
	if err := h.Server.reconfigureWG(); err != nil {
		message := fmt.Sprintf("Error reconfiguring WireGuard: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return false
	}
	return true
}

func (h UserHandler) createConfigGenerateKeyPair(w http.ResponseWriter, username string, name string) {
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		message := fmt.Sprintf("Error generating private key: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	clientPublicKey := clientPrivateKey.PublicKey()
	createConfigResponse := h.newConfig(username, clientPublicKey.String(), name)
	response := createConfigAndKeyPairResponse{
		ClientPrivateKey: clientPrivateKey.String(),
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

func (h UserHandler) createConfig(w http.ResponseWriter, username string, publicKey string, name string) {
	response := h.newConfig(username, publicKey, name)

	if !h.reconfigureWGHTTP(w) {
		return
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h UserHandler) deleteConfig(w http.ResponseWriter, username string, publicKey string) {
	h.Server.mutex.Lock()
	defer h.Server.mutex.Unlock()
	userConfig := h.Server.Config.Users[username]
	if userConfig == nil {
		http.Error(w, fmt.Sprintf("User '%s' not found", username), http.StatusNotFound)
		return
	}

	if userConfig.Clients[publicKey] == nil {
		message := fmt.Sprintf("Config with public key '%s' not found for user '%s", publicKey, username)
		http.Error(w, message, http.StatusNotFound)
		return
	}

	delete(userConfig.Clients, publicKey)

	if !h.reconfigureWGHTTP(w) {
		return
	}

	w.WriteHeader(http.StatusOK)
}

// setDisabled disables or enables a user and returns if the value was changed
func (h UserHandler) setDisabled(username string, disabled bool) bool {
	h.Server.mutex.Lock()
	defer h.Server.mutex.Unlock()
	userConfig := h.Server.Config.GetUserConfig(username)
	if userConfig.IsDisabled == disabled {
		return false
	}
	userConfig.IsDisabled = disabled
	return true
}

func (h UserHandler) setDisabledHTTP(w http.ResponseWriter, username string, disabled bool, conflictMessage string) {
	if !h.setDisabled(username, disabled) {
		http.Error(w, conflictMessage, http.StatusConflict)
	}

	if !h.reconfigureWGHTTP(w) {
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h UserHandler) disableUser(w http.ResponseWriter, username string) {
	h.setDisabledHTTP(w, username, true, fmt.Sprintf("User %s was already disabled.", username))
}

func (h UserHandler) enableUser(w http.ResponseWriter, username string) {
	h.setDisabledHTTP(w, username, false, fmt.Sprintf("User %s was already enabled.", username))
}

const form = "application/x-www-form-urlencoded"

func (h UserHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, url string, username string) {
	firstSegment, _ := ShiftPath(url)
	switch firstSegment {
	case "config":
		receivedPublicKey := req.Form.Get("public_key")
		if receivedPublicKey == "" {
			switch req.Method {
			case http.MethodGet:
				h.getConfigs(w, username)
			case http.MethodPost:
				name := req.Form.Get("name")
				if name == "" {
					contentType := req.Header.Get("Content-Type")
					if contentType != form {
						message := fmt.Sprintf("Content-Type '%s' was not equal to %s'", contentType, form)
						http.Error(w, message, http.StatusUnsupportedMediaType)
						return
					}
					http.Error(w, "No config name supplied.", http.StatusBadRequest)
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
				//todo: same code as above
				name := req.Form.Get("name")
				if name == "" {
					contentType := req.Header.Get("Content-Type")
					if contentType != form {
						message := fmt.Sprintf("Content-Type '%s' was not equal to %s'", contentType, form)
						http.Error(w, message, http.StatusUnsupportedMediaType)
						return
					}
					http.Error(w, "No config name supplied.", http.StatusBadRequest)
					return
				}
				h.createConfig(w, username, publicKey.String(), name)
			case http.MethodDelete:
				h.deleteConfig(w, username, publicKey.String())
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
