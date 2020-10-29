package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/fantostisch/wireguard-daemon/internal/api"
	"github.com/fantostisch/wireguard-daemon/wgmanager"
)

var (
	//nolint
	tlsCertDir = "."
	//nolint
	tlsKeyDir = "."

	initStorage = flag.Bool("init", false, "Create config file.")
	storageFile = flag.String("storage-file", "./storage.json", "File used for storing data")

	listen      = flag.String("listen", "127.0.0.1:8080", "API listen address")
	wgInterface = flag.String("wg-interface", "wg0", "WireGuard network interface name")
)

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	wgManager, err := wgmanager.New(*wgInterface)
	if err != nil {
		log.Fatal("Error creating WireGuard manager: ", err)
	}

	if *initStorage {
		err = api.NewFileStorage(*storageFile)
		if err != nil {
			log.Fatal("Error creating file for storage: ", err)
		}
		return
	}

	storage, err := api.ReadFile(*storageFile)
	if err != nil {
		log.Fatal("Error reading stored data. "+
			"If you have not created a config file yet, create one using --init. Error: ", err)
	}
	server, err := api.NewServer(storage, wgManager, *wgInterface)
	if server == nil || err != nil {
		log.Fatal("Error creating server: ", err)
	}
	startErr := server.Start(*listen)
	if startErr != nil {
		fmt.Println("Error starting server: ", startErr)
		return
	}
}

//nolint
func getTlsConfig() *tls.Config {
	caCertFile := filepath.Join(tlsCertDir, "ca.crt")
	certFile := filepath.Join(tlsCertDir, "server.crt")
	keyFile := filepath.Join(tlsKeyDir, "server.key")

	keyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	caCertPem, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatal(err)
	}

	trustedCaPool := x509.NewCertPool()
	if !trustedCaPool.AppendCertsFromPEM(caCertPem) {
	}

	return &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    trustedCaPool,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
	}
}
