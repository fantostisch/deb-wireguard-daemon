package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/fantostisch/wireguard-daemon/pkg/wgmanager"
	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type TestWGManager struct {
	configureWG            error
	getConnectionsPeerList []wgtypes.Peer
	getConnectionsError    error
}

func (wgm TestWGManager) ConfigureWG(privateKey string, users []wgmanager.User) error {
	return wgm.configureWG
}

func (wgm TestWGManager) GetConnections() ([]wgtypes.Peer, error) {
	return wgm.getConnectionsPeerList, wgm.getConnectionsError
}

//todo: test written data instead of in memory data
func newServer(server *Server) {
	var ipAddr, ipNet, _ = net.ParseCIDR("10.0.0.1/8")

	*server = Server{
		IPAddr:        ipAddr,
		clientIPRange: ipNet,
		wgManager:     TestWGManager{},
		Storage: &FileStorage{
			filePath: "/dev/null",
			Data: Data{
				PrivateKey: "server_private_key",
				PublicKey:  "server_public_key",
				Users: map[string]*UserConfig{
					peterUsername: &UserConfig{
						Clients: map[string]*ClientConfig{
							"public/key1=": &ClientConfig{
								Name: "Client config 1",
								IP:   net.IPv4(10, 0, 0, 1),
							},
							"Peters/Very+Rand0m/Public+Key/For+H1s/Phonc=": &ClientConfig{
								Name: "Client config 2",
								IP:   net.IPv4(10, 0, 0, 2),
							},
							"public+key3=": &ClientConfig{
								Name: "Client config 3",
								IP:   net.IPv4(10, 0, 0, 3),
							},
						},
					},
				},
			},
		},
	}
}

var server *Server = &Server{}

var apiRouter = API{
	UserHandler: UserHandler{Server: server},
}

func setup() {
	newServer(server)
}

var expIPString = "10.0.0.4"

const peterUsername = "Peter @ /K.org"

func testHTTPStatus(t *testing.T, w httptest.ResponseRecorder, exp int) {
	got := w.Code
	if got != exp {
		t.Errorf("Status code %d is not the expected %d. Response body: %s", got, exp, w.Body)
	}
}

func TestGetConfigs(t *testing.T) {
	setup()
	respRec := httptest.NewRecorder()
	parameters := url.Values{
		"user_id": {peterUsername},
	}
	req, _ := http.NewRequest(http.MethodGet, "/config?"+parameters.Encode(), nil)
	apiRouter.ServeHTTP(respRec, req)
	testHTTPStatus(t, *respRec, http.StatusOK)
	got := map[string]*ClientConfig{}
	err := json.NewDecoder(respRec.Body).Decode(&got)
	if err != nil {
		t.Errorf("Error decoding json: %s", err)
	}
	exp := server.Storage.Data.Users[peterUsername].Clients
	if !reflect.DeepEqual(got, exp) {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}

func TestGetConfigsUnknownUser(t *testing.T) {
	setup()
	respRec := httptest.NewRecorder()
	parameters := url.Values{
		"user_id": {"George"},
	}
	req, _ := http.NewRequest(http.MethodGet, "/config?"+parameters.Encode(), nil)
	apiRouter.ServeHTTP(respRec, req)
	testHTTPStatus(t, *respRec, http.StatusOK)
	got := respRec.Body.String()
	exp := "{}\n"
	if got != exp {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}

func TestGetConfigsUserWithoutConfigs(t *testing.T) {
	setup()
	username := "Eric"
	publicKey := testCreateConfigGenerateKeyPair(t, username)
	testDeleteConfig(t, username, publicKey.String())

	respRec := httptest.NewRecorder()
	parameters := url.Values{
		"user_id": {username},
	}
	req, _ := http.NewRequest(http.MethodGet, "/config?"+parameters.Encode(), nil)
	apiRouter.ServeHTTP(respRec, req)
	testHTTPStatus(t, *respRec, http.StatusOK)
	got := respRec.Body.String()
	exp := "{}\n"
	if got != exp {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}

func TestEmptyUsername(t *testing.T) {
	respRec := httptest.NewRecorder()
	requestBody := url.Values{
		"name": {"Name1"},
	}
	req, _ := http.NewRequest(http.MethodPost, "/config?user_id=", bytes.NewBufferString(requestBody.Encode()))
	apiRouter.ServeHTTP(respRec, req)
	testHTTPStatus(t, *respRec, http.StatusNotFound) //todo: should be http.StatusBadRequest
}

//todo: test creating config multiple times with same public key
func testCreateConfig(t *testing.T, username string) {
	expName := "+/ My Little Phone 16 +/"

	publicKey := "RuvRcz3zuwz/3xMqqh2ZvL+NT3W2v6J60rMnHtRiOE8="
	parameters := url.Values{
		"user_id":    {username},
		"public_key": {publicKey},
	}
	requestBody := url.Values{
		"name": {expName},
	}
	reqURL := "/config?" + parameters.Encode()
	req, _ := http.NewRequest(http.MethodPost, reqURL, bytes.NewBufferString(requestBody.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testHTTPStatus(t, *respRec, http.StatusOK)

	type response struct {
		IP              string
		ServerPublicKey string
	}

	{
		got := response{}

		err := json.NewDecoder(respRec.Body).Decode(&got)
		if err != nil {
			t.Errorf("Error decoding JSON: %s", err)
		}

		exp := response{
			IP:              expIPString,
			ServerPublicKey: server.Storage.Data.PublicKey,
		}

		if got != exp {
			t.Errorf("Got: %v, Wanted: %v", got, exp)
		}
	}

	{
		got := *server.Storage.Data.Users[username].Clients[publicKey]

		exp := ClientConfig{
			Name:     expName,
			IP:       net.ParseIP(expIPString),
			Modified: got.Modified, //todo: test
		}

		if !cmp.Equal(got, exp) {
			t.Errorf("Got: %v, Wanted: %v", got, exp)
		}
	}
}

func TestCreateConfig(t *testing.T) {
	var tests = []struct {
		testName string
		username string
	}{
		{"Create config for new user", "Emma"},
		{"Create config for existing user", peterUsername},
	}
	for _, tt := range tests {
		setup()
		t.Run(tt.testName, func(t *testing.T) { testCreateConfig(t, tt.username) })
	}
}

func testCreateConfigGenerateKeyPair(t *testing.T, username string) wgtypes.Key {
	expName := "+/ My Little Phone 16 +/"

	parameters := url.Values{
		"user_id": {username},
	}
	requestBody := url.Values{
		"name": {expName},
	}
	requestBodyString := bytes.NewBufferString(requestBody.Encode())
	req, _ := http.NewRequest(http.MethodPost, "/config?"+parameters.Encode(), requestBodyString)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testHTTPStatus(t, *respRec, http.StatusOK)

	type response struct {
		ClientPrivateKey string
		IP               string
		ServerPublicKey  string
	}

	var clientPrivateKey string

	{
		got := response{}

		err := json.NewDecoder(respRec.Body).Decode(&got)
		if err != nil {
			t.Errorf("Error decoding JSON: %s", err)
		}

		exp := response{
			ClientPrivateKey: got.ClientPrivateKey, //todo: test
			IP:               expIPString,
			ServerPublicKey:  server.Storage.Data.PublicKey,
		}

		if got != exp {
			t.Errorf("Got: %v, Wanted: %v", got, exp)
		}

		clientPrivateKey = got.ClientPrivateKey
	}

	var publicKey wgtypes.Key

	{
		key, err := wgtypes.ParseKey(clientPrivateKey)
		if err != nil {
			t.Errorf("Could not parse private key: %s", err)
		}

		publicKey = key.PublicKey()

		got := *server.Storage.Data.Users[username].Clients[publicKey.String()]

		exp := ClientConfig{
			Name:     expName,
			IP:       net.ParseIP(expIPString),
			Modified: got.Modified, //todo: test
		}

		if !cmp.Equal(got, exp) {
			t.Errorf("Got: %v, Wanted: %v", got, exp)
		}
	}
	return publicKey
}

func TestCreateConfigGenerateKeyPair(t *testing.T) {
	setup()
	testCreateConfigGenerateKeyPair(t, peterUsername)
}

func testDeleteConfig(t *testing.T, username string, publicKey string) {
	parameters := url.Values{
		"user_id":    {username},
		"public_key": {publicKey},
	}
	req, _ := http.NewRequest(http.MethodDelete, "/config?"+parameters.Encode(), nil)

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testHTTPStatus(t, *respRec, http.StatusOK)

	config, exists := server.Storage.Data.Users[username].Clients[publicKey]
	if exists {
		t.Error("Config exists")
	}
	if config != nil {
		t.Error(config, "not nil")
	}
}

func TestDeleteConfig(t *testing.T) {
	setup()
	testDeleteConfig(t, peterUsername, "Peters/Very+Rand0m/Public+Key/For+H1s/Phone=")
}

func testDisableUser(t *testing.T, username string, expCode int) {
	parameters := url.Values{
		"user_id": {username},
	}
	req, _ := http.NewRequest(http.MethodPost, "/disable_user?"+parameters.Encode(), nil)

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testHTTPStatus(t, *respRec, expCode)

	disabled := server.Storage.Data.Users[username].IsDisabled
	if !disabled {
		t.Error("User not disabled.")
	}
}

func testEnableUser(t *testing.T, username string, expCode int) {
	parameters := url.Values{
		"user_id": {username},
	}
	req, _ := http.NewRequest(http.MethodPost, "/enable_user?"+parameters.Encode(), nil)

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testHTTPStatus(t, *respRec, expCode)

	disabled := server.Storage.Data.Users[username].IsDisabled
	if disabled {
		t.Error("User disabled.")
	}
}

func TestDisablingAndEnablingUser(t *testing.T) {
	setup()
	var tests = []struct {
		testName     string
		username     string
		expCode      int
		testFunction func(t *testing.T, username string, expCode int)
	}{
		{"Disable new user", "Emma", http.StatusOK, testDisableUser},
		{"Disable existing user Peter", peterUsername, http.StatusOK, testDisableUser},
		{"Enable Emma", "Emma", http.StatusOK, testEnableUser},
		{"Enable Peter", peterUsername, http.StatusOK, testEnableUser},

		{"Enable new user", "Pierre", http.StatusConflict, testEnableUser},
		{"Disable Pierre", "Pierre", http.StatusOK, testDisableUser},
		{"Enable Pierre", "Pierre", http.StatusOK, testEnableUser},
		{"Enable Pierre when he is already enabled", "Pierre", http.StatusConflict, testEnableUser},

		{"Disable Pierre", "Pierre", http.StatusOK, testDisableUser},
		{"Disable Pierre when he is already disabled", "Pierre", http.StatusConflict, testDisableUser},
		{"Enable Pierre", "Pierre", http.StatusOK, testEnableUser},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) { tt.testFunction(t, tt.username, tt.expCode) })
	}
}

func TestWireGuardReconfigureError(t *testing.T) {
	setup()
	server.wgManager = TestWGManager{
		configureWG: errors.New("oops"),
	}

	testDisableUser(t, peterUsername, http.StatusInternalServerError)
	testEnableUser(t, peterUsername, http.StatusInternalServerError)
}
