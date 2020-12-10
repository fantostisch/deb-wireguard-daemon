package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var wgAPIRouter = API{}

func TestGetConnections(t *testing.T) {
	petersPublicKeyString := "Peters/Rand0m/Public/+/Key/For+H1s/Notebook="
	petersPublicKey, _ := wgtypes.ParseKey(petersPublicKeyString)
	t1 := time.Date(2020, 10, 12, 14, 05, 52, 4, time.UTC)

	arthursPublicKeyString := "Arthurs/Rand0m/Public/+/Key/On+H1s/Notebook="
	arthursPublicKey, _ := wgtypes.ParseKey(arthursPublicKeyString)
	t2 := time.Date(2020, 10, 12, 14, 06, 52, 4, time.UTC)

	peerList := []wgtypes.Peer{
		wgtypes.Peer{
			PublicKey:    petersPublicKey,
			PresharedKey: wgtypes.Key{},
			Endpoint: &net.UDPAddr{
				IP:   net.IPv4(3, 141, 59, 26),
				Port: 4000,
				Zone: "",
			},
			PersistentKeepaliveInterval: 0,
			LastHandshakeTime:           t1,
			ReceiveBytes:                9,
			TransmitBytes:               2,
			AllowedIPs: []net.IPNet{net.IPNet{
				IP:   net.IPv4(2, 71, 82, 81),
				Mask: net.CIDRMask(32, 32),
			}},
			ProtocolVersion: 0,
		}, {
			PublicKey:    arthursPublicKey,
			PresharedKey: wgtypes.Key{},
			Endpoint: &net.UDPAddr{
				IP:   net.IPv4(6, 62, 60, 70),
				Port: 5000,
				Zone: "zone",
			},
			PersistentKeepaliveInterval: 0,
			LastHandshakeTime:           t2,
			ReceiveBytes:                15,
			TransmitBytes:               25,
			AllowedIPs: []net.IPNet{net.IPNet{
				IP:   net.IPv4(1, 61, 6, 255),
				Mask: net.CIDRMask(32, 32),
			}},
			ProtocolVersion: 0,
		},
	}

	wgAPIRouter.ConnectionHandler.wgManager = TestWGManager{
		getConnectionsPeerList: peerList,
	}

	storage := FileStorage{
		filePath: "/dev/null",
		data: data{
			Users: map[UserID]*User{
				peterUsername: &User{
					Clients: map[PublicKey]ClientConfig{
						PublicKey{petersPublicKey}: ClientConfig{},
					},
				},
				"Arthur": {
					Clients: map[PublicKey]ClientConfig{
						PublicKey{arthursPublicKey}: {},
					},
				},
			},
		},
	}

	wgAPIRouter.ConnectionHandler.storage = &storage

	respRec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/client_connections", nil)
	wgAPIRouter.ServeHTTP(respRec, req)
	testHTTPStatus(t, *respRec, http.StatusOK)

	type ConnectionString struct {
		PublicKey  string   `json:"publicKey"`
		AllowedIPs []string `json:"allowedIPs"`
	}

	var got map[string][]ConnectionString
	err := json.NewDecoder(respRec.Body).Decode(&got)
	if err != nil {
		t.Errorf("Error decoding json: %s", err)
	}

	exp := map[string][]ConnectionString{
		peterUsername: {ConnectionString{
			PublicKey:  petersPublicKeyString,
			AllowedIPs: []string{"2.71.82.81/32"},
		}}, "Arthur": {ConnectionString{
			PublicKey:  arthursPublicKeyString,
			AllowedIPs: []string{"1.61.6.255/32"},
		}},
	}
	if !cmp.Equal(got, exp) {
		t.Error("Diff: ", cmp.Diff(exp, got))
	}
}
