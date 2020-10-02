package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Configuration struct {
	configPath string
	PrivateKey string
	PublicKey  string
	Users      map[string]*UserConfig
}

type UserConfig struct {
	Clients map[string]*ClientConfig
}

type ClientConfig struct {
	Name     string `json:"name"`
	Info     string `json:"info"`
	IP       net.IP `json:"ip"`
	Modified string `json:"modified"`
}

// Generate server configuration
func newServerConfig(cfgPath string) *Configuration {
	keys, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Panic("Fatal", err)
	}
	config := &Configuration{
		configPath: cfgPath,
		PrivateKey: keys.String(),
		PublicKey:  keys.PublicKey().String(),
		Users:      make(map[string]*UserConfig),
	}
	file, err := os.Open(filepath.Clean(cfgPath))
	if err == nil {
		if err = json.NewDecoder(file).Decode(config); err != nil {
			log.Fatal("Failing to decode: ", err)
		}
		log.Print("Read server config from file : ", cfgPath)
		log.Print("------------------------------------------")
	} else if os.IsNotExist(err) {
		log.Print("No configuration file found. Creating one ", cfgPath)
		err = config.Write()
	}
	log.Print("PublicKey: ", config.PublicKey, "     PrivateKey: ", config.PrivateKey)
	if err != nil {
		log.Print("Error", err)
	}
	return config
}

// Write config
func (config *Configuration) Write() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(config.configPath, data, 0600)
}

// Get user configuration, create one if it doesn't exist
func (config *Configuration) GetUserConfig(user string) *UserConfig {
	us, ok := config.Users[user]
	if !ok {
		us = &UserConfig{
			Clients: make(map[string]*ClientConfig),
		}
		config.Users[user] = us
	}
	return us
}

func NewClientConfig(name string, info string, ip net.IP) ClientConfig {
	now := time.Now().Format(time.RFC3339)
	config := ClientConfig{
		Name:     name,
		Info:     info,
		IP:       ip,
		Modified: now,
	}
	return config
}
