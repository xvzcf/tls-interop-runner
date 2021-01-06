package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type testCase interface {
	ClientConfig() (*tls.Config, error)
	ClientConnectionHandler(*tls.Conn) error
	ServerConfig() (*tls.Config, error)
	ServerConnectionHandler(*tls.Conn) error
}

var baseServerConfig, baseClientConfig *tls.Config

func init() {
	// Setup the base client configuration.
	pem, err := ioutil.ReadFile("/testdata/root.crt")
	if err != nil {
		log.Fatal(err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(pem)
	baseClientConfig = &tls.Config{
		RootCAs: certPool,
	}

	// Setup the base server configuration.
	serverCert, err := tls.LoadX509KeyPair(
		"/testdata/example.crt",
		"/testdata/example.key",
	)
	if err != nil {
		log.Fatal(err)
	}

	clientFacingCert, err := tls.LoadX509KeyPair(
		"/testdata/client_facing.crt",
		"/testdata/client_facing.key",
	)
	if err != nil {
		log.Fatal(err)
	}

	baseServerConfig = &tls.Config{
		Certificates: []tls.Certificate{
			serverCert,
			clientFacingCert,
		},
	}
}

type testCaseDC struct{}

func (t testCaseDC) ClientConfig() (*tls.Config, error) {
	config := baseClientConfig.Clone()
	config.SupportDelegatedCredential = true
	return config, nil
}

func (t testCaseDC) ServerConfig() (*tls.Config, error) {
	config := baseClientConfig.Clone()
	return config, nil
}

func (t testCaseDC) ClientConnectionHandler(conn *tls.Conn) error {
	if conn.ConnectionState().VerifiedDC == nil {
		return errors.New("Failed to verify a delegated credential")
	}
	return nil
}

func (t testCaseDC) ServerConnectionHandler(conn *tls.Conn) error {
	// TODO
	return errors.New("NOT IMPLEMENTED")
}

type echTestResult struct {
	serverStatus tls.EXP_EventECHServerStatus
}

func (r *echTestResult) eventHandler(event tls.EXP_Event) {
	switch e := event.(type) {
	case tls.EXP_EventECHServerStatus:
		r.serverStatus = e
	}
}

type testCaseECHAccept struct{}

func (t testCaseECHAccept) ClientConfig() (*tls.Config, error) {
	base64ECHConfigs, err := ioutil.ReadFile("/testdata/ech_configs")
	if err != nil {
		return nil, err
	}

	rawECHConfigs, err := base64.StdEncoding.DecodeString(string(base64ECHConfigs))
	if err != nil {
		return nil, err
	}

	echConfigs, err := tls.UnmarshalECHConfigs(rawECHConfigs)
	if err != nil {
		return nil, err
	}

	config := baseClientConfig.Clone()
	config.ClientECHConfigs = echConfigs
	config.ECHEnabled = true
	return config, nil
}

func (t testCaseECHAccept) ServerConfig() (*tls.Config, error) {
	base64ECHKeys, err := ioutil.ReadFile("/testdata/ech_key")
	if err != nil {
		return nil, err
	}

	rawECHKeys, err := base64.StdEncoding.DecodeString(string(base64ECHKeys))
	if err != nil {
		return nil, err
	}

	echKeys, err := tls.EXP_UnmarshalECHKeys(rawECHKeys)
	if err != nil {
		return nil, err
	}

	echProvider, err := tls.EXP_NewECHKeySet(echKeys)
	if err != nil {
		return nil, err
	}

	config := baseServerConfig.Clone()
	config.ServerECHProvider = echProvider
	config.ECHEnabled = true
	return config, nil
}

func (t testCaseECHAccept) connectionHandler(conn *tls.Conn) error {
	if !conn.ConnectionState().ECHAccepted {
		return errors.New("ECH not accepted")
	}
	return nil
}

func (t testCaseECHAccept) ClientConnectionHandler(conn *tls.Conn) error {
	return t.connectionHandler(conn)
}

func (t testCaseECHAccept) ServerConnectionHandler(conn *tls.Conn) error {
	return t.connectionHandler(conn)
}

var testCaseHandlers = map[string]testCase{
	"dc":         testCaseDC{},
	"ech-accept": testCaseECHAccept{},
}

func doClient(t testCase) error {
	config, err := t.ClientConfig()
	if err != nil {
		return err
	}

	c, err := tls.Dial("tcp", "example.com:4433", config)
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
		// Skip this test case.
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
