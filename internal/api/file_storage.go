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
	Users map[UserID]*User `json:"users"`
}

func NewFileStorage(filePath string) error {
	storage := &FileStorage{
		filePath: filePath,
		data: data{
			Users: map[UserID]*User{},
		}}
	switch _, err := os.Open(filepath.Clean(filePath)); {
	case err == nil:
		return fmt.Errorf("file '%s' already exists: ", filePath)
	case os.IsNotExist(err):
		storage.dataMutex.Lock()
		return storage.write()
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
// Mutex should already be locked, we will unlock it before writing everything to disk.
func (s *FileStorage) write() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	s.dataMutex.Unlock()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.filePath, data, 0600)
}

func (s *FileStorage) GetUserClients(username UserID) map[PublicKey]ClientConfig {
	s.dataMutex.Lock()
	defer s.dataMutex.Unlock()

	userConfig := s.data.Users[username]
	if userConfig == nil {
		return map[PublicKey]ClientConfig{}
	}
	return userConfig.Clients
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
func (s *FileStorage) UpdateOrCreateConfig(username UserID, publicKey PublicKey, config ClientConfig) (bool, error) {
	s.dataMutex.Lock()

	allocatedIPs := s.getAllocatedIPsUnsafe()

	allocated := false
	for _, allocatedIP := range allocatedIPs {
		if allocatedIP.Equal(config.IP) {
			allocated = true
			break
		}
	}
	if allocated {
		s.dataMutex.Unlock()
		return false, nil
	}

	s.getOrCreateUser(username).Clients[publicKey] = config
	return true, s.write()
}

// Return true if config was successfully deleted, false otherwise.
func (s *FileStorage) DeleteConfig(username UserID, publicKey PublicKey) (bool, error) {
	s.dataMutex.Lock()

	user := s.data.Users[username]
	if user == nil {
		s.dataMutex.Unlock()
		return false, nil
	}
	_, exist := user.Clients[publicKey]
	if !exist {
		s.dataMutex.Unlock()
		return false, nil
	}
	delete(user.Clients, publicKey)
	return true, s.write()
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
func (s *FileStorage) SetDisabled(username UserID, disabled bool) (bool, error) {
	s.dataMutex.Lock()

	user := s.getOrCreateUser(username)
	if user.IsDisabled == disabled {
		s.dataMutex.Unlock()
		return false, nil
	}
	user.IsDisabled = disabled
	return true, s.write()
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
