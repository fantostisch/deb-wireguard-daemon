package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
)

type FileStorage struct {
	filePath  string
	dataMutex sync.RWMutex
	data      data
}

type data struct {
	PrivateKey PrivateKey       `json:"privateKey"`
	PublicKey  PublicKey        `json:"publicKey"`
	Users      map[UserID]*User `json:"users"`
}

func NewFileStorage(filePath string, privateKey PrivateKey, publicKey PublicKey) error {
	storage := &FileStorage{
		filePath: filePath,
		data: data{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			Users:      map[UserID]*User{},
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
	if err = json.NewDecoder(file).Decode(&storage.data); err != nil {
		return nil, fmt.Errorf("failed to parse storage file: %w", err)
	}
	return storage, nil
}

// Write config to disk
func (s *FileStorage) Write() error {
	s.dataMutex.Lock()
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		s.dataMutex.Unlock()
		return err
	}
	s.dataMutex.Unlock()
	return ioutil.WriteFile(s.filePath, data, 0600)
}

func (s *FileStorage) GetServerPrivateKey() PublicKey {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	return s.data.PrivateKey
}

func (s *FileStorage) GetServerPublicKey() PublicKey {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	return s.data.PublicKey
}

func (s *FileStorage) GetUserConfig(username UserID) (User, bool) {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	userConfig := s.data.Users[username]
	if userConfig == nil {
		return User{}, false
	}
	return *userConfig, true
}

func (s *FileStorage) GetUsernameAndConfig(publicKey PublicKey) (UserID, ClientConfig, error) {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	for username, u := range s.data.Users {
		for pk, config := range u.Clients {
			if publicKey == pk {
				return username, config, nil
			}
		}
	}
	return "", ClientConfig{}, errors.New("no user found for this public key")
}

// Caller should have locked dataMutex
func (s *FileStorage) getOrCreateUser(username UserID) *User {
	user := s.data.Users[username]
	if user == nil {
		user = &User{
			IsDisabled: false,
			Clients:    map[PublicKey]ClientConfig{},
		}
		s.data.Users[username] = user
	}
	return user
}

//todo: changing the name should not also update the ip
func (s *FileStorage) UpdateOrCreateConfig(username UserID, publicKey PublicKey, config ClientConfig) bool {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	allocatedIPs := s.getAllocatedIPsUnsafe()

	allocated := false
	for _, allocatedIP := range allocatedIPs {
		if allocatedIP.Equal(config.IP) {
			allocated = true
			break
		}
	}
	if allocated {
		return false
	}

	s.getOrCreateUser(username).Clients[publicKey] = config
	return true
}

// Return true if config was successfully deleted, false otherwise.
func (s *FileStorage) DeleteConfig(username UserID, publicKey PublicKey) bool {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	user := s.data.Users[username]
	if user == nil {
		return false
	}
	_, exist := user.Clients[publicKey]
	if !exist {
		return false
	}
	delete(user.Clients, publicKey)
	return true
}

func (s *FileStorage) GetEnabledUsers() []User {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	enabledUsers := make([]User, len(s.data.Users))
	for _, user := range s.data.Users {
		if !user.IsDisabled {
			enabledUsers = append(enabledUsers, *user)
		}
	}
	return enabledUsers
}

// SetDisabled disables or enables a user and returns if the value was changed
func (s *FileStorage) SetDisabled(username UserID, disabled bool) bool {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	user := s.getOrCreateUser(username)
	if user.IsDisabled == disabled {
		return false
	}
	user.IsDisabled = disabled
	return true
}

func (s *FileStorage) getAllocatedIPsUnsafe() []net.IP {
	allocatedIPs := []net.IP{}
	for _, user := range s.data.Users {
		for _, client := range user.Clients {
			allocatedIPs = append(allocatedIPs, client.IP)
		}
	}
	return allocatedIPs
}

func (s *FileStorage) GetAllocatedIPs() []net.IP {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()
	return s.getAllocatedIPsUnsafe()
}
