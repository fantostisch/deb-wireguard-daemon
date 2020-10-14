package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/fantostisch/wireguard-daemon/pkg/wgmanager"

	"github.com/fantostisch/wireguard-daemon/internal/api"
)

var (
	//nolint
	tlsCertDir = "."
	//nolint
	tlsKeyDir     = "."
	wgPort        = 51820
	initStorage   = flag.Bool("init", false, "Create config file.")
	storageFile   = flag.String("storage-file", "./conf.json", "File used for storing data")
	listenAddress = flag.String("listen-address", ":8080", "Address to listen on")
	wgInterface   = flag.String("wg-interface", "wg0", "WireGuard network interface name")
)

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	wgManager, err := wgmanager.New(*wgInterface, wgPort)
	if err != nil {
		log.Fatal("Error creating WireGuard manager: ", err)
	}

	if *initStorage {
		privateKey, err := wgManager.GeneratePrivateKey()
		if err != nil {
			log.Fatal("Error generating private key: ", err)
		}
		err = api.NewFileStorage(*storageFile, privateKey, privateKey.PublicKey())
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
	server := api.NewServer(storage, wgManager, *wgInterface)

	// Stop server on CTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range c {
			stopErr := server.Stop()
			if stopErr != nil {
				fmt.Println("Error stopping server: ", stopErr)
			}
			os.Exit(0)
		}
	}()

	startErr := server.Start()
	if startErr != nil {
		fmt.Println("Error starting server: ", startErr)
		return
	}
	startAPIErr := server.StartAPI(*listenAddress)
	if startAPIErr != nil {
		fmt.Println("Error starting API: ", startAPIErr)
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
