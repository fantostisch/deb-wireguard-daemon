package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParsingUrl(t *testing.T) {
	url := "first/second/"
	exp := "second"
	_, remainingURL := ShiftPath(url)
	got, _ := ShiftPath(remainingURL)
	if got != exp {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}

func TestNotEnoughSegments(t *testing.T) {
	url := "first/second/"
	exp := ""
	_, remainingURL := ShiftPath(url)
	_, remainingURL2 := ShiftPath(remainingURL)
	got, _ := ShiftPath(remainingURL2)
	if got != exp {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}

var ipAddr, ipNet, _ = net.ParseCIDR("10.0.0.1/8")

var server = &Server{
	IPAddr:        ipAddr,
	clientIPRange: ipNet,
	Config: &WgConf{
		configPath: "/dev/null",
		PrivateKey: "server_private_key",
		PublicKey:  "server_public_key",
		Users: map[string]*UserConf{
			"peter": &UserConf{
				Clients: map[string]*ClientConfig{
					"1": &ClientConfig{
						Name: "Client config 1",
						IP:   net.IPv4(10, 0, 0, 1),
					},
					"2": &ClientConfig{
						Name: "Client config 2",
						IP:   net.IPv4(10, 0, 0, 2),
					},
					"3": &ClientConfig{
						Name: "Client config 3",
						IP:   net.IPv4(10, 0, 0, 3),
					},
				},
			},
		},
	},
}

var apiRouter = API{
	UserHandler: UserHandler{Server: server},
}

func testHTTPOkStatus(t *testing.T, statusCode int) {
	exp := http.StatusOK
	if statusCode != exp {
		t.Errorf("Status code %d is not the expected %d", statusCode, exp)
	}
}

func TestGetConfigs(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/user/peter/configs", nil)
	apiRouter.ServeHTTP(responseWriter, req)
	testHTTPOkStatus(t, responseWriter.Code)
	got := map[string]*ClientConfig{}
	err := json.NewDecoder(responseWriter.Body).Decode(&got)
	if err != nil {
		t.Errorf("Error decoding json: %s", err)
	}
	exp := server.Config.Users["peter"].Clients
	if !reflect.DeepEqual(got, exp) {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}
