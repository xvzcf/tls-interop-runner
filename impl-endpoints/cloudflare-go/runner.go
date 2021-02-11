// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type testCase interface {
	ClientConfig() (*tls.Config, error)
	ClientConnectionHandler(*tls.Conn, error) error
	ServerConfig() (*tls.Config, error)
	ServerConnectionHandler(*tls.Conn, error) error
}

var baseServerConfig, baseClientConfig *tls.Config

func init() {
	// Setup the base client configuration.
	pem, err := ioutil.ReadFile("/test-inputs/root.crt")
	if err != nil {
		log.Fatal(err)
	}

	clientKeyLog, err := os.OpenFile("/test-outputs/client_keylog", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(pem)
	baseClientConfig = &tls.Config{
		RootCAs:      certPool,
		KeyLogWriter: clientKeyLog,
	}

	// Setup the base server configuration.
	serverCert, err := tls.LoadX509KeyPair(
		"/test-inputs/example.crt",
		"/test-inputs/example.key",
	)
	if err != nil {
		log.Fatal(err)
	}

	clientFacingCert, err := tls.LoadX509KeyPair(
		"/test-inputs/client-facing.crt",
		"/test-inputs/client-facing.key",
	)
	if err != nil {
		log.Fatal(err)
	}

	serverKeyLog, err := os.OpenFile("/test-outputs/server_keylog", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	baseServerConfig = &tls.Config{
		Certificates: []tls.Certificate{
			serverCert,
			clientFacingCert,
		},
		KeyLogWriter: serverKeyLog,
	}
}

// The "dc" test case in which the client indicates support for DCs and the
// server uses a DC for authentication. See draft-ietf-tls-subcerts.
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

func (t testCaseDC) ClientConnectionHandler(conn *tls.Conn, err error) error {
	if err != nil {
		return fmt.Errorf("Unexpected error: \"%s\"", err)
	}
	if conn.ConnectionState().VerifiedDC == nil {
		return errors.New("Failed to verify a delegated credential")
	}
	return nil
}

func (t testCaseDC) ServerConnectionHandler(conn *tls.Conn, err error) error {
	// TODO
	return errors.New("NOT IMPLEMENTED")
}

// The "ech-accept" test case in which a client offers the ECH extension and
// the server accepts. The client verifies server name "backend.com". See
// draft-ietf-tls-esni.
//
// TODO(cjpatton): Check via validatepcap that:
// (1) client sent ECH in CH; and
// (2) SNI = "example.com".
type testCaseECHAccept struct{}

func (t testCaseECHAccept) ClientConfig() (*tls.Config, error) {
	return echClientConfig("/test-inputs/ech_configs")
}

func (t testCaseECHAccept) ServerConfig() (*tls.Config, error) {
	return echServerConfig("/test-inputs/ech_key")
}

func (t testCaseECHAccept) connectionHandler(conn *tls.Conn, err error) error {
	if err != nil {
		return fmt.Errorf("Unexpected error: \"%s\"", err)
	}

	st := conn.ConnectionState()
	if !st.ECHAccepted {
		return errors.New("ECH not accepted")
	}
	log.Printf("Connection completed with backend server \"%s\"", st.ServerName)
	return nil
}

func (t testCaseECHAccept) ClientConnectionHandler(conn *tls.Conn, err error) error {
	return t.connectionHandler(conn, err)
}

func (t testCaseECHAccept) ServerConnectionHandler(conn *tls.Conn, err error) error {
	return t.connectionHandler(conn, err)
}

// The "ech-reject" test case in which the client offers ECH with stale configs
// and the server rejects. The client verifies server name "client-facing.com",
// then aborts the handshake with an "ech_required" alert. See
// draft-ietf-tls-esni.
//
// TODO(cjpatton): Check via validatepcap that:
// (1) client sent ECH in CH;
// (2) server sent ECH in EE; and
// (3) SNI = "client-facing.com".
type testCaseECHReject struct{}

func (t testCaseECHReject) ClientConfig() (*tls.Config, error) {
	return echClientConfig("/test-inputs/ech_configs_invalid")
}

func (t testCaseECHReject) ServerConfig() (*tls.Config, error) {
	return echServerConfig("/test-inputs/ech_key")
}

func (t testCaseECHReject) ClientConnectionHandler(conn *tls.Conn, err error) error {
	if err == nil {
		return errors.New("Handshake completed successfully; expected error")
	}
	if err.Error() != "tls: ech: rejected" {
		return fmt.Errorf("Unexpected error: \"%s\"", err)
	}
	log.Print("Aborted the connection as expected")
	return nil
}

func (t testCaseECHReject) ServerConnectionHandler(conn *tls.Conn, err error) error {
	if err != nil {
		return fmt.Errorf("Unexpected error: \"%s\"", err)
	}
	if conn.ConnectionState().ECHAccepted {
		return errors.New("ECH accepted; expected rejection")
	}
	log.Printf("Connection completed with client-facing server \"%s\"", conn.ConnectionState().ServerName)
	return nil
}

func echServerConfig(keysFile string) (*tls.Config, error) {
	base64ECHKeys, err := ioutil.ReadFile(keysFile)
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

func echClientConfig(configsFile string) (*tls.Config, error) {
	base64ECHConfigs, err := ioutil.ReadFile(configsFile)
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

var testCaseHandlers = map[string]testCase{
	"dc":         testCaseDC{},
	"ech-accept": testCaseECHAccept{},
	"ech-reject": testCaseECHReject{},
}

func doClient(t testCase) error {
	config, err := t.ClientConfig()
	if err != nil {
		return err
	}

	c, err := tls.Dial("tcp", "example.com:4433", config)
	if err == nil {
		defer c.Close()
	}
	return t.ClientConnectionHandler(c, err)
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
	if err == nil {
		defer s.Close()
	}
	return t.ServerConnectionHandler(s, err)
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

	log.SetFlags(0)
	if *role == "client" {
		if err := doClient(handler); err != nil {
			log.Fatal(err)
		}
	} else if *role == "server" {
		if err := doServer(handler); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatalf("Unknown role \"%s\"", *role)
	}
}
