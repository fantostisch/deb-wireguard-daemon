package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type APIHandler struct {
	Server *Server
}

// Get current username
func (h APIHandler) identify(res http.ResponseWriter) {
	var user = "anonymous" //todo
	err := json.NewEncoder(res).Encode(struct{ User string }{user})
	if err != nil {
		log.Print(err)
		res.WriteHeader(http.StatusInternalServerError)
	}
}

func (h APIHandler) status(w http.ResponseWriter) {
	if wgStatus {
		log.Print("WireGuard server is running")
		w.WriteHeader(http.StatusCreated)
	} else {
		log.Print("WireGuard server is off ")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h APIHandler) activate(w http.ResponseWriter) {
	if wgStatus {
		log.Print("Server is already running")
		w.WriteHeader(http.StatusOK)
		return
	}
	log.Print("Starting WireGuard server.....")
	err := h.Server.Start()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Print(" WireGuard server started")
	w.WriteHeader(http.StatusOK)
}

func (h APIHandler) deactivate(w http.ResponseWriter) {
	if !wgStatus {
		log.Print("The server is already turned off")
		w.WriteHeader(http.StatusOK)
		return
	}
	log.Print("Shutting down WireGuard server")
	stopErr := h.Server.Stop()
	startErr := h.Server.StartAPI()
	if stopErr != nil || startErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h APIHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var head string
	head, req.URL.Path = ShiftPath(req.URL.Path)
	switch head {
	case "identify":
		switch req.Method {
		case http.MethodGet:
			h.identify(w)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "status":
		switch req.Method {
		case http.MethodGet:
			h.status(w)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "activate":
		switch req.Method {
		case http.MethodGet:
			h.activate(w)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "deactivate":
		switch req.Method {
		case http.MethodGet:
			h.deactivate(w)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, req)
	}
}
