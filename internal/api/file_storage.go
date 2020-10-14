package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"
)

type FileStorage struct {
	filePath string
	Data     Data
}

type Data struct {
	PrivateKey PrivateKey             `json:"privateKey"`
	PublicKey  PublicKey              `json:"publicKey"`
	Users      map[UserID]*UserConfig `json:"users"`
}

func NewFileStorage(filePath string, privateKey PrivateKey, publicKey PublicKey) error {
	storage := &FileStorage{
		filePath: filePath,
		Data: Data{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			Users:      map[UserID]*UserConfig{},
		}}
	switch _, err := os.Open(filepath.Clean(filePath)); {
	case err == nil:
		return fmt.Errorf("file '%s' already exists: ", filePath)
	case os.IsNotExist(err):
		return storage.Write()
	default:
		return err
	}
}

func ReadFile(filePath string) (*FileStorage, error) {
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return nil, fmt.Errorf("could not read storage file: %w", err)
	}
	storage := &FileStorage{
		filePath: filePath,
	}
	if err = json.NewDecoder(file).Decode(&storage.Data); err != nil {
		return nil, fmt.Errorf("failed to parse storage file: %w", err)
	}
	return storage, nil
}

// Write config
func (storage *FileStorage) Write() error {
	data, err := json.MarshalIndent(storage.Data, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(storage.filePath, data, 0600)
}

// Get user configuration, create one if it doesn't exist
func (storage *FileStorage) GetUserConfig(username UserID) *UserConfig {
	user := storage.Data.Users[username]
	if user == nil {
		user = &UserConfig{
			IsDisabled: false,
			Clients:    map[PublicKey]*ClientConfig{},
		}
		storage.Data.Users[username] = user
	}
	return user
}

func NewClientConfig(name string, ip net.IP) ClientConfig {
	now := TimeJ{time.Now().UTC()}
	config := ClientConfig{
		Name:     name,
		IP:       ip,
		Modified: now,
	}
	return config
}

func (storage *FileStorage) GetUsernameAndConfig(publicKey PublicKey) (UserID, ClientConfig, error) {
	for username, u := range storage.Data.Users {
		for pk, config := range u.Clients {
			if publicKey == pk {
				return username, *config, nil
			}
		}
	}
	return "", ClientConfig{}, errors.New("no user found for this public key")
}
