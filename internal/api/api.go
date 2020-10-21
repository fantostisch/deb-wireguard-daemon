package api

import (
	"fmt"
	"net/http"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type API struct {
	UserHandler       UserHandler
	ConnectionHandler ConnectionHandler
}

func checkContentType(w http.ResponseWriter, req *http.Request) bool {
	if req.Method != http.MethodPost {
		return true
	}
	contentType := req.Header.Get("Content-Type")
	const form = "application/x-www-form-urlencoded"
	if contentType != form {
		message := fmt.Sprintf("Content-Type '%s' was not equal to %s'", contentType, form)
		http.Error(w, message, http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

// getRequiredPOSTValue gets a value from the HTTP parameters. If the value is not available an error response will be
// written and an empty string will be returned.
func getRequiredPOSTValue(w http.ResponseWriter, req *http.Request, key string) string {
	value := req.FormValue(key)
	if value == "" {
		if !checkContentType(w, req) {
			return ""
		}
		message := fmt.Sprintf("'%s'  was not supplied.", key)
		http.Error(w, message, http.StatusBadRequest)
		return ""
	}
	return value
}

func getUserID(w http.ResponseWriter, req *http.Request) (UserID, bool) {
	username := req.FormValue("user_id")
	if username == "" {
		if !checkContentType(w, req) {
			return "", false
		}
		http.Error(w, "user_id was not supplied.", http.StatusBadRequest)
		return "", false
	}
	return UserID(username), true
}

func getPublicKey(w http.ResponseWriter, req *http.Request) (PublicKey, bool) {
	receivedPublicKey := getRequiredPOSTValue(w, req, "public_key")
	if receivedPublicKey == "" {
		return PublicKey{}, false
	}
	publicKey, err := wgtypes.ParseKey(receivedPublicKey)
	if err != nil {
		message := fmt.Sprintf("Invalid public key: '%s'. %s", receivedPublicKey, err)
		http.Error(w, message, http.StatusBadRequest)
		return PublicKey{}, false
	}
	return PublicKey{publicKey}, true
}

// nolint: gocyclo
func (h API) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	URL := req.URL.EscapedPath()[1:] // remove leading '/'
	switch URL {
	case "configs":
		username, e := getUserID(w, req)
		if !e {
			return
		}
		switch req.Method {
		case http.MethodGet:
			h.UserHandler.getConfigs(w, username)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	case "create_config":
		username, e := getUserID(w, req)
		if !e {
			return
		}
		switch req.Method {
		case http.MethodPost:
			publicKey, e := getPublicKey(w, req)
			if !e {
				return
			}
			name := getRequiredPOSTValue(w, req, "name")
			if name == "" {
				return
			}
			h.UserHandler.createConfig(w, username, publicKey, name)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

	case "create_config_and_key_pair":
		username, e := getUserID(w, req)
		if !e {
			return
		}
		switch req.Method {
		case http.MethodPost:
			name := getRequiredPOSTValue(w, req, "name")
			if name == "" {
				return
			}
			h.UserHandler.createConfigGenerateKeyPair(w, username, name)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	case "delete_config":
		switch req.Method {
		case http.MethodPost:
			username, e := getUserID(w, req)
			if !e {
				return
			}
			publicKey, e := getPublicKey(w, req)
			if !e {
				return
			}
			h.UserHandler.deleteConfig(w, username, publicKey)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "disable_user":
		switch req.Method {
		case http.MethodPost:
			username, e := getUserID(w, req)
			if !e {
				return
			}
			h.UserHandler.disableUser(w, username)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "enable_user":
		switch req.Method {
		case http.MethodPost:
			username, e := getUserID(w, req)
			if !e {
				return
			}
			h.UserHandler.enableUser(w, username)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "client_connections":
		switch req.Method {
		case http.MethodGet:
			h.ConnectionHandler.getConnections(w)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, req)
	}
}
