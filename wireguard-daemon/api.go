package main

import (
	"flag"
	"net/http"
	"path"
	"regexp"
	"strings"
)

var (
	wgEndpoint   = flag.String("wg-endpoint", "127.0.0.1:51820", "WireGuard endpoint address")
	wgAllowedIPs = flag.String("wg-allowed-ips", "0.0.0.0/0", "WireGuard client allowed ips")
	wgDNS        = flag.String("wg-dns", "8.8.8.8", "WireGuard client DNS server (optional)")
	filenameRe   = regexp.MustCompile("[^a-zA-Z0-9]+")
)

type API struct {
	APIHandler  APIHandler
	UserHandler UserHandler
}

// Based on https://blog.merovius.de/2017/06/18/how-not-to-use-an-http-router.html
// ShiftPath splits off the first component of p, which will be cleaned of
// relative components before processing. head will never contain a slash and
// tail will always be a rooted path without trailing slash.
func ShiftPath(p string) (head, tail string) {
	p = path.Clean("/" + p)
	i := strings.Index(p[1:], "/") + 1
	if i <= 0 {
		return p[1:], ""
	}
	return p[1:i], p[i:]
}

func (h API) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	firstSegment, remaining := ShiftPath(req.URL.Path)
	switch firstSegment {
	case "user":
		username, remainingAfterUser := ShiftPath(remaining)
		req.URL.Path = remainingAfterUser
		h.UserHandler.ServeHTTP(w, req, username)
	default:
		h.APIHandler.ServeHTTP(w, req)
	}
}

func (serv *Server) StartAPI() error {
	var router http.Handler = API{
		APIHandler:  APIHandler{Server: serv},
		UserHandler: UserHandler{Server: serv},
	}
	return http.ListenAndServe(*listenAddr, router)
}
