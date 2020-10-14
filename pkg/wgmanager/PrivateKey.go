package wgmanager

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PrivateKey struct {
	wgtypes.Key
}

func (k *PrivateKey) UnmarshalText(data []byte) error {
	key, err := wgtypes.ParseKey(string(data))
	if err != nil {
		return fmt.Errorf("failed to unmarshal key to json: %v", err)
	}
	*k = PrivateKey{key}
	return nil
}

func (k PrivateKey) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

func (k PrivateKey) PublicKey() PublicKey {
	return PublicKey{k.Key.PublicKey()}
}
