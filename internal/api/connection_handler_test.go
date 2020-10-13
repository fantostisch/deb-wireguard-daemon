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
		Data: Data{
			Users: map[string]*UserConfig{
				peterUsername: &UserConfig{
					Clients: map[string]*ClientConfig{
						petersPublicKeyString: &ClientConfig{Name: "Peters config"},
					},
				},
				"Arthur": {
					Clients: map[string]*ClientConfig{
						arthursPublicKeyString: {Name: "Arthur's config"},
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
	var got map[string][]Connection
	err := json.NewDecoder(respRec.Body).Decode(&got)
	if err != nil {
		t.Errorf("Error decoding json: %s", err)
	}

	exp := map[string][]Connection{
		peterUsername: {Connection{
			PublicKey:  petersPublicKeyString,
			Name:       "Peters config",
			AllowedIPs: []string{"2.71.82.81/32"},
		}}, "Arthur": {Connection{
			PublicKey:  arthursPublicKeyString,
			Name:       "Arthur's config",
			AllowedIPs: []string{"1.61.6.255/32"},
		}},
	}
	if !cmp.Equal(got, exp) {
		t.Errorf("Got: %v, Wanted: %v", got, exp)
	}
}
