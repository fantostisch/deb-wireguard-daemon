package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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

var server = &Server{
	Config: &WgConf{
		Users: map[string]*UserConf{
			"peter": &UserConf{
				Clients: map[string]*ClientConfig{
					"1": &ClientConfig{
						Name: "Client config 1",
					},
					"2": &ClientConfig{
						Name: "Client config 2",
					},
					"3": &ClientConfig{
						Name: "Client config 3",
					},
				},
			},
		},
	},
}

var apiRouter = API{
	APIHandler:  APIHandler{Server: server},
	UserHandler: UserHandler{Server: server},
}

func testHTTPOkStatus(t *testing.T, statusCode int) {
	exp := http.StatusOK
	if statusCode != exp {
		t.Errorf("Status code %d is not the expected %d", statusCode, exp)
	}
}

func TestIdentify(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/identify", nil)
	apiRouter.ServeHTTP(responseWriter, req)

	got := responseWriter.Body.String()
	exp := "{\"User\":\"anonymous\"}\n"
	if got != exp {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}

func TestGetClients(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/user/peter/clients", nil)
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

func TestGetClient(t *testing.T) {
	responseWriter := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/user/peter/clients/2", nil)
	apiRouter.ServeHTTP(responseWriter, req)
	testHTTPOkStatus(t, responseWriter.Code)
	got := responseWriter.Body.String()
	exp := "[Interface]"
	if !strings.HasPrefix(got, exp) {
		t.Errorf("Got: %v, Wanted to start with: %v", got, exp)
	}
}
