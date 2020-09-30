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
)

var (
	//nolint
	tlsCertDir = "."
	//nolint
	tlsKeyDir   = "."
	wgPort      = 51820
	dataDir     = flag.String("data-dir", "", "Directory used for storage")
	listenAddr  = flag.String("listen-address", ":8080", "Address to listen to")
	wgInterface = flag.String("wg-interface", "wg0", "WireGuard network interface name")
)

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	s := NewServer()

	// Stop server on CTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range c {
			stopErr := s.Stop()
			if stopErr != nil {
				fmt.Print("Error stopping server: ", stopErr)
			}
			os.Exit(0)
		}
	}()

	startErr := s.Start()
	if startErr != nil {
		fmt.Print("Error starting server: ", startErr)
	}
	startAPIErr := s.StartAPI()
	if startAPIErr != nil {
		fmt.Println("Error starting API: ", startAPIErr)
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
