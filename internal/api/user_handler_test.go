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
	"time"

	"github.com/fantostisch/wireguard-daemon/wgmanager"
	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type TestWGManager struct {
	configureWG            error
	getConnectionsPeerList []wgtypes.Peer
	getConnectionsError    error
}

func (wgm TestWGManager) GetPublicKey() (PrivateKey, error) {
	return PrivateKey{}, nil
}

func (wgm TestWGManager) GeneratePrivateKey() (PrivateKey, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	return PrivateKey{privateKey}, err
}

func (wgm TestWGManager) ConfigureWG(peers []wgmanager.Peer) error {
	return wgm.configureWG
}

func (wgm TestWGManager) AddPeers(peers []wgmanager.Peer) error {
	return wgm.configureWG
}

func (wgm TestWGManager) RemovePeers(keys []PublicKey) error {
	return wgm.configureWG
}

func (wgm TestWGManager) GetConnections() ([]wgtypes.Peer, error) {
	return wgm.getConnectionsPeerList, wgm.getConnectionsError
}

const petersPublicKey1String = "1+Peters/+/Rand0m//Public+Key/For+H1s/Phonc="
const petersPublicKey2String = "2+Peters/+/Rand0m//Public+Key/For+H1s/Phonc="
const petersPublicKey3String = "3+Peters/+/Rand0m//Public+Key/For+H1s/Phonc="

//todo: test public api but not in memory data
func newServer(server *Server) {
	var ipAddr, ipNet, _ = net.ParseCIDR("10.0.0.1/8")

	wgManager := TestWGManager{}

	privateKey, _ := wgManager.GeneratePrivateKey()
	publicKey := privateKey.PublicKey()

	petersPublicKey1, _ := wgtypes.ParseKey(petersPublicKey1String)
	petersPublicKey2, _ := wgtypes.ParseKey(petersPublicKey2String)
	petersPublicKey3, _ := wgtypes.ParseKey(petersPublicKey3String)

	*server = Server{
		IPAddr:        ipAddr,
		clientIPRange: ipNet,
		wgManager:     wgManager,
		wgPublicKey:   publicKey,
		Storage: &FileStorage{
			filePath: "/dev/null",
			data: data{
				Users: map[UserID]*User{
					peterUsername: &User{
						Clients: map[PublicKey]ClientConfig{
							PublicKey{petersPublicKey1}: ClientConfig{
								IP:       net.IPv4(10, 0, 0, 1),
								Modified: TimeJ{time.Date(2020, 10, 13, 17, 52, 14, 4, time.UTC)},
							},
							PublicKey{petersPublicKey2}: ClientConfig{
								IP:       net.IPv4(10, 0, 0, 2),
								Modified: TimeJ{time.Date(2020, 10, 13, 17, 53, 14, 4, time.UTC)},
							},
							PublicKey{petersPublicKey3}: ClientConfig{
								IP:       net.IPv4(10, 0, 0, 3),
								Modified: TimeJ{time.Date(2020, 10, 13, 17, 54, 14, 4, time.UTC)},
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

func testError(t *testing.T, w httptest.ResponseRecorder, apiError *Error) {
	if apiError == nil {
		testHTTPStatus(t, w, http.StatusOK)
		return
	}
	switch apiError.Name {
	case "internal_server_error":
		testHTTPStatus(t, w, http.StatusInternalServerError)
	default:
		testHTTPStatus(t, w, http.StatusBadRequest)
		got := JSONError{}
		err := json.NewDecoder(w.Body).Decode(&got)
		if err != nil {
			t.Errorf("Error decoding JSON: %s", err)
		}
	}
}

type ClientConfigStrings struct {
	IP       string `json:"ip"`
	Modified string `json:"modified"`
}

func TestGetConfigs(t *testing.T) {
	setup()
	respRec := httptest.NewRecorder()
	parameters := url.Values{
		"user_id": {peterUsername},
	}
	req, _ := http.NewRequest(http.MethodGet, "/configs?"+parameters.Encode(), nil)
	apiRouter.ServeHTTP(respRec, req)
	testHTTPStatus(t, *respRec, http.StatusOK)
	got := map[string]*ClientConfigStrings{}
	err := json.NewDecoder(respRec.Body).Decode(&got)
	if err != nil {
		t.Errorf("Error decoding json: %s", err)
	}

	exp := map[string]*ClientConfigStrings{
		petersPublicKey1String: {
			IP:       "10.0.0.1",
			Modified: "2020-10-13T17:52:14Z",
		},
		petersPublicKey2String: {
			IP:       "10.0.0.2",
			Modified: "2020-10-13T17:53:14Z",
		},
		petersPublicKey3String: {
			IP:       "10.0.0.3",
			Modified: "2020-10-13T17:54:14Z",
		},
	}

	if !reflect.DeepEqual(got, exp) {
		t.Error("Diff: ", cmp.Diff(exp, got))
	}
}

func TestGetConfigsUnknownUser(t *testing.T) {
	setup()
	respRec := httptest.NewRecorder()
	parameters := url.Values{
		"user_id": {"George"},
	}
	req, _ := http.NewRequest(http.MethodGet, "/configs?"+parameters.Encode(), nil)
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
	req, _ := http.NewRequest(http.MethodGet, "/configs?"+parameters.Encode(), nil)
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
		"user_id": {""},
	}
	body := bytes.NewBufferString(requestBody.Encode())
	req, _ := http.NewRequest(http.MethodPost, "/create_config_and_key_pair", body)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	apiRouter.ServeHTTP(respRec, req)
	testHTTPStatus(t, *respRec, http.StatusBadRequest)
}

//todo: test creating config multiple times with same public key
func testCreateConfig(t *testing.T, username string) {
	publicKeyString := "RuvRcz3zuwz/3xMqqh2ZvL+NT3W2v6J60rMnHtRiOE8="
	requestBody := url.Values{
		"user_id":    {username},
		"public_key": {publicKeyString},
	}
	req, _ := http.NewRequest(http.MethodPost, "/create_config", bytes.NewBufferString(requestBody.Encode()))
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
			ServerPublicKey: server.GetPublicKey().String(),
		}

		if got != exp {
			t.Errorf("Got: %v, Wanted: %v", got, exp)
		}
	}

	{
		publicKey, _ := wgtypes.ParseKey(publicKeyString)
		got := server.Storage.data.Users[UserID(username)].Clients[PublicKey{publicKey}]

		exp := ClientConfig{
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
	requestBody := url.Values{
		"user_id": {username},
	}
	requestBodyString := bytes.NewBufferString(requestBody.Encode())
	req, _ := http.NewRequest(http.MethodPost, "/create_config_and_key_pair", requestBodyString)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testHTTPStatus(t, *respRec, http.StatusOK)

	type response struct {
		ClientPrivateKey string
		ClientPublicKey  string
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
			ClientPublicKey:  got.ClientPublicKey,  //todo: test
			IP:               expIPString,
			ServerPublicKey:  server.GetPublicKey().String(),
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

		got := server.Storage.data.Users[UserID(username)].Clients[PublicKey{publicKey}]

		exp := ClientConfig{
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

func testDeleteConfig(t *testing.T, username string, publicKeyString string) {
	requestBody := url.Values{
		"user_id":    {username},
		"public_key": {publicKeyString},
	}
	req, _ := http.NewRequest(http.MethodPost, "/delete_config", bytes.NewBufferString(requestBody.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testHTTPStatus(t, *respRec, http.StatusOK)

	publicKey, _ := wgtypes.ParseKey(publicKeyString)
	_, exists := server.Storage.data.Users[UserID(username)].Clients[PublicKey{publicKey}]
	if exists {
		t.Error("Config exists")
	}
}

func TestDeleteConfig(t *testing.T) {
	setup()
	testDeleteConfig(t, peterUsername, petersPublicKey2String)
	testDeleteConfig(t, peterUsername, petersPublicKey1String)
	testDeleteConfig(t, peterUsername, petersPublicKey3String)
}

func testDisableUser(t *testing.T, username string, apiError *Error) {
	parameters := url.Values{
		"user_id": {username},
	}
	req, _ := http.NewRequest(http.MethodPost, "/disable_user?"+parameters.Encode(), nil)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testError(t, *respRec, apiError)

	disabled := server.Storage.data.Users[UserID(username)].IsDisabled
	if !disabled {
		t.Error("User not disabled.")
	}
}

func testEnableUser(t *testing.T, username string, apiError *Error) {
	parameters := url.Values{
		"user_id": {username},
	}
	req, _ := http.NewRequest(http.MethodPost, "/enable_user?"+parameters.Encode(), nil)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	respRec := httptest.NewRecorder()
	apiRouter.ServeHTTP(respRec, req)

	testError(t, *respRec, apiError)

	disabled := server.Storage.data.Users[UserID(username)].IsDisabled
	if disabled {
		t.Error("User disabled.")
	}
}

func TestDisablingAndEnablingUser(t *testing.T) {
	setup()
	var tests = []struct {
		testName     string
		username     string
		apiError     *Error
		testFunction func(t *testing.T, username string, apiError *Error)
	}{
		{"Disable new user", "Emma", nil, testDisableUser},
		{"Disable existing user Peter", peterUsername, nil, testDisableUser},
		{"Enable Emma", "Emma", nil, testEnableUser},
		{"Enable Peter", peterUsername, nil, testEnableUser},

		{"Enable new user", "Pierre", &UserAlreadyEnabled, testEnableUser},
		{"Disable Pierre", "Pierre", nil, testDisableUser},
		{"Enable Pierre", "Pierre", nil, testEnableUser},
		{"Enable Pierre when he is already enabled", "Pierre", &UserAlreadyEnabled, testEnableUser},

		{"Disable Pierre", "Pierre", nil, testDisableUser},
		{"Disable Pierre when he is already disabled", "Pierre", &UserAlreadyDisabled, testDisableUser},
		{"Enable Pierre", "Pierre", nil, testEnableUser},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) { tt.testFunction(t, tt.username, tt.apiError) })
	}
}

func TestWireGuardReconfigureError(t *testing.T) {
	setup()
	server.wgManager = TestWGManager{
		configureWG: errors.New("oops"),
	}

	testDisableUser(t, peterUsername, &Error{"internal_server_error"})
	testEnableUser(t, peterUsername, &Error{"internal_server_error"})
}
