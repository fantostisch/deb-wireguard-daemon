package api

import (
	"net/http"
	"path"
	"strings"
)

type API struct {
	UserHandler       UserHandler
	ConnectionHandler ConnectionHandler
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
	URL := req.URL.EscapedPath()
	username := req.FormValue("user_id")
	if username != "" {
		h.UserHandler.ServeHTTP(w, req, URL, UserID(username))
		return
	}
	h.ConnectionHandler.ServeHTTP(w, req, URL)
}

func (s *Server) StartAPI(listenAddress string) error {
	var router http.Handler = API{
		UserHandler:       UserHandler{Server: s},
		ConnectionHandler: ConnectionHandler{wgManager: s.wgManager, storage: s.Storage},
	}
	return http.ListenAndServe(listenAddress, router)
}
