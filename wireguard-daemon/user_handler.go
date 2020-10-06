package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"

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

type createConfigRequest struct {
	Name string `json:"name"`
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

func (h UserHandler) createConfigGenerateKeyPair(w http.ResponseWriter, username string, req createConfigRequest) {
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		message := fmt.Sprintf("Error generating private key: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
	clientPublicKey := clientPrivateKey.PublicKey()
	createConfigResponse := h.newConfig(username, clientPublicKey.String(), req.Name)
	response := createConfigAndKeyPairResponse{
		ClientPrivateKey: clientPrivateKey.String(),
		IP:               createConfigResponse.IP,
		ServerPublicKey:  createConfigResponse.ServerPublicKey,
	}

	if err := h.Server.reconfigureWG(); err != nil {
		message := fmt.Sprintf("Error reconfiguring WireGuard: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		message := fmt.Sprintf("Error encoding response as JSON: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}
}

func (h UserHandler) createConfig(w http.ResponseWriter, username string, publicKey string, req createConfigRequest) {
	response := h.newConfig(username, publicKey, req.Name)

	if err := h.Server.reconfigureWG(); err != nil {
		message := fmt.Sprintf("Error reconfiguring WireGuard: %s", err)
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

	if err := h.Server.reconfigureWG(); err != nil {
		message := fmt.Sprintf("Error reconfiguring WireGuard: %s", err)
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h UserHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, remainingURL string, username string) {
	config, secondRemaining := ShiftPath(remainingURL)
	if config == "config" {
		receivedPublicKeyEscaped, _ := ShiftPath(secondRemaining)
		if receivedPublicKeyEscaped == "" {
			switch req.Method {
			case http.MethodGet:
				h.getConfigs(w, username)
			case http.MethodPost:
				createRequest := createConfigRequest{}
				if err := json.NewDecoder(req.Body).Decode(&createRequest); err != nil {
					http.Error(w, fmt.Sprintf("Could not decode request body: %s \n %s", err, req.Body), http.StatusBadRequest)
					return
				}
				h.createConfigGenerateKeyPair(w, username, createRequest)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
		} else {
			receivedPublicKey, err := url.PathUnescape(receivedPublicKeyEscaped)
			if err != nil {
				message := fmt.Sprintf("Public key '%s' was not properly escaped: %s", receivedPublicKey, err)
				http.Error(w, message, http.StatusBadRequest)
				return
			}
			publicKey, err := wgtypes.ParseKey(receivedPublicKey)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid public key: '%s'. %s", receivedPublicKey, err), http.StatusBadRequest)
				return
			}
			switch req.Method {
			case http.MethodPost:
				createRequest := createConfigRequest{}
				if err := json.NewDecoder(req.Body).Decode(&createRequest); err != nil {
					http.Error(w, fmt.Sprintf("Could not decode request body: %s \n %s", err, req.Body), http.StatusBadRequest)
					return
				}
				h.createConfig(w, username, publicKey.String(), createRequest)
			case http.MethodDelete:
				h.deleteConfig(w, username, publicKey.String())
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		}
	} else {
		http.NotFound(w, req)
	}
}
