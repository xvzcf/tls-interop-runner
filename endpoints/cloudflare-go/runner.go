// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

type TestHandler interface {
	Config() (*tls.Config, error)
	ConnectionHandler(*tls.Conn, error) error
}

// dcServerHandler implements the server's handler for the "dc" test case.
//
// in this test case,
type dcServerHandler struct {
	TestHandler
}

func (t *dcServerHandler) Config() (*tls.Config, error) {
	config := baseServerConfig.Clone()
	config.SupportDelegatedCredential = true

	raw, err := os.ReadFile("/test-inputs/dc.txt")
	if err != nil {
		log.Fatal(err)
	}
	dcRaw := bytes.Split(raw, []byte(","))

	dcDecoded := make([]byte, hex.DecodedLen(len(dcRaw[0])))
	n, err := hex.Decode(dcDecoded, dcRaw[0])
	if err != nil {
		log.Fatal(err)
	}
	dc, err := tls.UnmarshalDelegatedCredential(dcDecoded[:n])
	if err != nil {
		log.Fatal(err)
	}

	dcKeyDecoded := make([]byte, hex.DecodedLen(len(dcRaw[1])))
	n, err = hex.Decode(dcKeyDecoded, dcRaw[1])
	if err != nil {
		log.Fatal(err)
	}
	dcKey, err := x509.ParsePKCS8PrivateKey(dcKeyDecoded[:n])
	if err != nil {
		log.Fatal(err)
	}

	config.Certificates[0].DelegatedCredentials = append(config.Certificates[0].DelegatedCredentials, tls.DelegatedCredentialPair{dc, dcKey})
	return config, nil
}

func (t *dcServerHandler) ConnectionHandler(conn *tls.Conn, err error) error {
	if err != nil {
		return fmt.Errorf("Unexpected error: \"%s\"", err)
	}
	return nil
}

// dcClientHandler implements the client's handler for the "dc" test case.
//
// in this test case,
type dcClientHandler struct {
	TestHandler
}

func (t *dcClientHandler) Config() (*tls.Config, error) {
	config := baseClientConfig.Clone()
	config.SupportDelegatedCredential = true
	return config, nil
}

func (t *dcClientHandler) ConnectionHandler(conn *tls.Conn, err error) error {
	if err != nil {
		return fmt.Errorf("Unexpected error: \"%s\"", err)
	}
	if !conn.ConnectionState().VerifiedDC {
		return errors.New("Failed to verify a delegated credential")
	}
	return nil
}

// echAcceptClientHandler implements the client's handler for the "ech-accept"
// test case.
//
type echAcceptClientHandler struct {
	TestHandler
}

func (t *echAcceptClientHandler) Config() (*tls.Config, error) {
	return echClientConfig("/test-inputs/ech_configs")
}

func (t *echAcceptClientHandler) ConnectionHandler(conn *tls.Conn, err error) error {
	return echAcceptConnectionHandler(conn, err)
}

type echAcceptServerHandler struct {
	TestHandler
}

func (t *echAcceptServerHandler) Config() (*tls.Config, error) {
	return echServerConfig("/test-inputs/ech_key")
}

func (t *echAcceptServerHandler) ConnectionHandler(conn *tls.Conn, err error) error {
	return echAcceptConnectionHandler(conn, err)
}

func echAcceptConnectionHandler(conn *tls.Conn, err error) error {
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

type echRejectClientHandler struct{
	TestHandler
}

func (t *echRejectClientHandler) Config() (*tls.Config, error) {
	return echClientConfig("/test-inputs/ech_configs_invalid")
}

func (t *echRejectClientHandler) ConnectionHandler(conn *tls.Conn, err error) error {
	if err == nil {
		return errors.New("Handshake completed successfully; expected error")
	}
	if err.Error() != "tls: ech: rejected" {
		return fmt.Errorf("Unexpected error: \"%s\"", err)
	}
	log.Print("Aborted the connection as expected")
	return nil
}

type echRejectServerHandler struct {
	TestHandler
}

func (t *echRejectServerHandler) Config() (*tls.Config, error) {
	return echServerConfig("/test-inputs/ech_key")
}

func (t *echRejectServerHandler) ConnectionHandler(conn *tls.Conn, err error) error {
	if err != nil {
		return fmt.Errorf("Unexpected error: \"%s\"", err)
	}
	if conn.ConnectionState().ECHAccepted {
		return errors.New("ECH accepted; expected rejection")
	}
	log.Printf("Connection completed with client-facing server \"%s\"", conn.ConnectionState().ServerName)
	return nil
}

type testCase struct {
	Client, Server TestHandler
}

var testCaseHandlers = map[string]testCase{
	// The client indicates support for DCs and the server uses a DC for
	// authentication. See draft-ietf-tls-subcerts.
	"dc": {
		Client: &dcClientHandler{},
		Server: &dcServerHandler{},
	},

	// The client offers the ECH extension and the server accepts. The client
	// verifies server name "backend.com". See draft-ietf-tls-esni.
	//
	// TODO(cjpatton): Check via validatepcap that:
	// (1) client sent ECH in CH; and
	// (2) SNI = "example.com".
	"ech-accept": {
		Client: &echAcceptClientHandler{},
		Server: &echAcceptServerHandler{},
	},

	// The client offers ECH with stale configs and the server rejects. The
	// client verifies server name "client-facing.com", then aborts the
	// handshake with an "ech_required" alert. See draft-ietf-tls-esni.
	//
	// TODO(cjpatton): Check via validatepcap that:
	// (1) client sent ECH in CH;
	// (2) server sent ECH in EE; and
	// (3) SNI = "client-facing.com".
	"ech-reject": {
		Client: &echRejectClientHandler{},
		Server: &echRejectServerHandler{},
	},
}

func doClient(t TestHandler) error {
	config, err := t.Config()
	if err != nil {
		return err
	}

	c, err := tls.Dial("tcp", "example.com:4433", config)
	
	if c != nil {
		defer c.Close()
	}

	err = t.ConnectionHandler(c, err)

	if err != nil {
		return err
	}
	return nil
}

func doServer(t TestHandler) error {
	config, err := t.Config()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", ":4433")
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Print("Listening at ", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		go func() {
			s := tls.Server(conn, config)
			err = s.Handshake()
			if err == nil {
				defer s.Close()
			}
			err = t.ConnectionHandler(s, err)
			if err != nil {
				log.Print(err)
			}
		}()
	}
	return nil
}

func main() {
	testCase := flag.String("test", "", "Test case identifier")
	role := flag.String("role", "client", "Role string (client or server)")
	flag.Parse()

	handler, ok := testCaseHandlers[*testCase]
	if !ok {
		log.Println("Skipped unimplemented test case.")
		os.Exit(64)
	}

	log.SetFlags(0)
	if *role == "client" && handler.Client != nil {
		if err := doClient(handler.Client); err != nil {
			log.Fatal(err)
		}
	} else if *role == "server" && handler.Server != nil {
		if err := doServer(handler.Server); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("Skipped unimplemented role.")
		os.Exit(64)
	}
}
