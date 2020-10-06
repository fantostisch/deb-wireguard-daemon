package main

import (
	"fmt"
	"net/http"
	"path"
	"strings"
)

type API struct {
	UserHandler UserHandler
}

// Based on https://blog.merovius.de/2017/06/18/how-not-to-use-an-http-router.html
// ShiftPath splits off the first component of p, which will be cleaned of
// relative components before processing. head will never contain a slash and
// tail will always be a rooted path without trailing slash.
func ShiftPath(p string) (head string, tail string) {
	p = path.Clean("/" + p)
	i := strings.Index(p[1:], "/") + 1
	if i <= 0 {
		return p[1:], ""
	}
	return p[1:i], p[i:]
}

func (h API) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	firstSegment, _ := ShiftPath(req.URL.EscapedPath())
	switch firstSegment {
	case "config":
		if err := req.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("Could not parse request body: %s", err), http.StatusBadRequest)
			return
		}
		username := req.Form.Get("user_id")
		if username == "" {
			http.Error(w, "No user_id supplied.", http.StatusBadRequest)
			return
		}
		h.UserHandler.ServeHTTP(w, req, username)
	default:
		http.NotFound(w, req)
	}
}

func (serv *Server) StartAPI() error {
	var router http.Handler = API{
		UserHandler: UserHandler{Server: serv},
	}
	return http.ListenAndServe(*listenAddr, router)
}
