package main

import (
	"fmt"
	"net/http"
	"net/url"
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
	firstSegment, remaining := ShiftPath(req.URL.EscapedPath())
	switch firstSegment {
	case "user":
		usernameEscaped, remainingAfterUser := ShiftPath(remaining)
		username, err := url.PathUnescape(usernameEscaped)
		if err != nil {
			http.Error(w, fmt.Sprintf("Could not unescape user: %s", usernameEscaped), http.StatusBadRequest)
			return
		}
		h.UserHandler.ServeHTTP(w, req, remainingAfterUser, username)
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
