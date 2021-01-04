package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
)

func createBaseClientConfig() (*tls.Config, error) {
	certPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("/testdata/root.cert")
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(pem)
	return &tls.Config{RootCAs: certPool}, nil
}

func createBaseServerConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("/testdata/server.cert", "/testdata/server.key")
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

type testCase interface {
	ClientConfig() (*tls.Config, error)
	ClientConnectionHandler(*tls.Conn) error
	ServerConfig() (*tls.Config, error)
	ServerConnectionHandler(*tls.Conn) error
}

type delegatedCredentialTestCase struct {
}

func (c delegatedCredentialTestCase) ClientConfig() (*tls.Config, error) {
	config, err := createBaseClientConfig()
	if err != nil {
		return nil, err
	}

	config.SupportDelegatedCredential = true
	return config, nil
}

func (c delegatedCredentialTestCase) ClientConnectionHandler(conn *tls.Conn) error {
	if conn.ConnectionState().VerifiedDC == nil {
		return errors.New("Failed to verify a delegated credential")
	}
	return nil
}

func (c delegatedCredentialTestCase) ServerConfig() (*tls.Config, error) {
	config, err := createBaseServerConfig()
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (c delegatedCredentialTestCase) ServerConnectionHandler(conn *tls.Conn) error {
	// TODO
	return errors.New("NOT IMPLEMENTED")
}

var testCaseHandlers = map[string]testCase{
	"dc": delegatedCredentialTestCase{},
}

func doClient(t testCase) error {
	config, err := t.ClientConfig()
	if err != nil {
		return err
	}

	c, err := tls.Dial("tcp", "server:4433", config)
	if err != nil {
		return err
	}
	defer c.Close()
	log.Print("Handshake completed")

	return t.ClientConnectionHandler(c)
}

func doServer(t testCase) error {
	config, err := t.ServerConfig()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", ":4433")
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Print("Listening at ", ln.Addr())

	conn, err := ln.Accept()
	if err != nil {
		return err
	}

	s := tls.Server(conn, config)
	err = s.Handshake()
	if err != nil {
		return err
	}
	defer s.Close()
	log.Print("Handshake completed")

	return t.ServerConnectionHandler(s)
}

func main() {
	testCase := flag.String("test", "", "Test case identifier")
	role := flag.String("role", "client", "Role string (client or server)")
	flag.Parse()

	handler, ok := testCaseHandlers[*testCase]
	if !ok {
		// Skip this test case
		os.Exit(64)
	}

	if *role == "client" {
		if err := doClient(handler); err != nil {
			log.Fatal("Error: ", err)
		}
	} else if *role == "server" {
		if err := doServer(handler); err != nil {
			log.Fatal("Error: ", err)
		}
	} else {
		log.Fatalf("unknown role \"%s\"", *role)
	}
}
