package wgmanager

import "net"

type User struct {
	PublicKey string
	IP        net.IP
}

type IWGManager interface {
	ConfigureWG(privateKey string, users []User) error
}
