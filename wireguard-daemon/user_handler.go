package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

type UserHandler struct {
	Server *Server
}

// Get all configs of a user.
func (h UserHandler) getConfigs(w http.ResponseWriter, username string) {
	clients := map[string]*ClientConfig{}
	userConfig := h.Server.Config.Users[username]
	if userConfig != nil {
		clients = userConfig.Clients
	} else {
		log.Print("This user does not have clients")
	}

	err := json.NewEncoder(w).Encode(clients)

	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h UserHandler) getConfig(w http.ResponseWriter, username string, id int) {
	userConfig := h.Server.Config.Users[username]
	if userConfig == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	client := userConfig.Clients[strconv.Itoa(id)]
	if client == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	err := json.NewEncoder(w).Encode(client)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h UserHandler) createConfig(w http.ResponseWriter, r *http.Request, username string) {
	h.Server.mutex.Lock()
	defer h.Server.mutex.Unlock()

	cli := h.Server.Config.GetUserConfig(username)

	decoder := json.NewDecoder(r.Body)

	client := &ClientConfig{}
	err := decoder.Decode(&client)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if client.Name == "" {
		log.Print("No CLIENT NAME found.....USING DEFAULT...\"unnamed Client\"")
		client.Name = "Unnamed Client"
	}
	i := 0
	for k := range cli.Clients {
		n, err := strconv.Atoi(k)
		if err != nil {
			log.Print("There was an error strc CONV :: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if n > i {
			i = n
		}
	}
	i++
	log.Print("Allocating IP")
	ip := h.Server.allocateIP()
	log.Print("Creating Client Config")
	client = NewClientConfig(ip, client.Name, client.Info)
	cli.Clients[strconv.Itoa(i)] = client
	err = h.Server.reconfiguringWG()
	if err != nil {
		log.Print("error Reconfiguring :: ", err)
	}
	err = json.NewEncoder(w).Encode(client)
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (h UserHandler) editConfig(w http.ResponseWriter, req *http.Request, username string, clientID int) {
	usercfg := h.Server.Config.Users[username]
	if usercfg == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	client := usercfg.Clients[strconv.Itoa(clientID)]
	if client == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	cfg := ClientConfig{}

	if err := json.NewDecoder(req.Body).Decode(&cfg); err != nil {
		log.Print("Error parsing request: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Printf("EditClient: %#v", cfg)

	if cfg.Name != "" {
		client.Name = cfg.Name
	}

	if cfg.Info != "" {
		client.Info = cfg.Info
	}

	client.Modified = time.Now().Format(time.RFC3339)

	reconfigureErr := h.Server.reconfiguringWG()
	if reconfigureErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(client); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (h UserHandler) deleteConfig(w http.ResponseWriter, username string, clientID int) {
	usercfg := h.Server.Config.Users[username]
	if usercfg == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	client := strconv.Itoa(clientID)
	if usercfg.Clients[client] == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	delete(usercfg.Clients, client)
	reconfigureErr := h.Server.reconfiguringWG()
	if reconfigureErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Print("user", username, " ::: Deleted client:", client)

	w.WriteHeader(http.StatusOK)
}

func (h UserHandler) ServeHTTP(w http.ResponseWriter, req *http.Request, username string) {
	configs, secondRemaining := ShiftPath(req.URL.Path)
	clientID, _ := ShiftPath(secondRemaining)
	if configs == "configs" {
		if clientID == "" {
			switch req.Method {
			case http.MethodGet:
				h.getConfigs(w, username)
			case http.MethodPost:
				h.createConfig(w, req, username)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		} else {
			id, err := strconv.Atoi(clientID)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid user id: '%s'", clientID), http.StatusBadRequest)
				return
			}
			switch req.Method {
			case http.MethodGet:
				h.getConfig(w, username, id)
			case http.MethodPut:
				h.editConfig(w, req, username, id)
			case http.MethodPost:
				h.deleteConfig(w, username, id)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		}
	} else {
		http.NotFound(w, req)
	}
}
