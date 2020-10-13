package api

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type FileStorage struct {
	filePath string
	Data     Data
}

type Data struct {
	PrivateKey string
	PublicKey  string
	Users      map[string]*UserConfig
}

type UserConfig struct {
	IsDisabled bool
	Clients    map[string]*ClientConfig
}

type ClientConfig struct {
	Name     string `json:"name"`
	IP       net.IP `json:"ip"`
	Modified string `json:"modified"`
}

// Generate server configuration
func NewFileStorage(filePath string) *FileStorage {
	keys, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Panic("Fatal", err)
	}
	storage := &FileStorage{
		filePath: filePath,
		Data: Data{
			PrivateKey: keys.String(),
			PublicKey:  keys.PublicKey().String(),
			Users:      make(map[string]*UserConfig),
		}}
	file, err := os.Open(filepath.Clean(filePath))
	if err == nil {
		if err = json.NewDecoder(file).Decode(storage); err != nil {
			log.Fatal("Failing to decode: ", err)
		}
		log.Print("Read data from file : ", filePath)
		log.Print("------------------------------------------")
	} else if os.IsNotExist(err) {
		log.Print("No configuration file found. Creating one ", filePath)
		err = storage.Write()
	}
	log.Print("PublicKey: ", storage.Data.PublicKey, "     PrivateKey: ", storage.Data.PrivateKey)
	if err != nil {
		log.Print("Error", err)
	}
	return storage
}

// Write config
func (storage *FileStorage) Write() error {
	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(storage.filePath, data, 0600)
}

// Get user configuration, create one if it doesn't exist
func (storage *FileStorage) GetUserConfig(username string) *UserConfig {
	user := storage.Data.Users[username]
	if user == nil {
		user = &UserConfig{
			IsDisabled: false,
			Clients:    map[string]*ClientConfig{},
		}
		storage.Data.Users[username] = user
	}
	return user
}

func NewClientConfig(name string, ip net.IP) ClientConfig {
	now := time.Now().Format(time.RFC3339)
	config := ClientConfig{
		Name:     name,
		IP:       ip,
		Modified: now,
	}
	return config
}

func (storage *FileStorage) GetUsernameAndConfig(publicKey string) (string, ClientConfig, error) {
	for username, u := range storage.Data.Users {
		for pk, config := range u.Clients {
			if publicKey == pk {
				return username, *config, nil
			}
		}
	}
	return "", ClientConfig{}, errors.New("no user found for this public key")
}
