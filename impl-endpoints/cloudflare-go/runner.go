package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"os"
)

type testCase interface {
	ClientConfig() (*tls.Config, error)
	ClientConnectionHandler(*tls.Conn) bool
	// ServerConfig() *tls.Config
	// ServerListenerHandler(net.Listener) bool
}

type delegatedCredentialTestCase struct {
}

func (c delegatedCredentialTestCase) ClientConfig() (*tls.Config, error) {
	certPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("/certs/rootCA.pem")
	if err != nil {
		return nil, err
	}

	certPool.AppendCertsFromPEM(pem)
	return &tls.Config{
		RootCAs:                    certPool,
		SupportDelegatedCredential: true,
	}, nil
}

func (c delegatedCredentialTestCase) ClientConnectionHandler(conn *tls.Conn) bool {
	state := conn.ConnectionState()
	return state.VerifiedDC != nil
}

var testCaseHandlers = map[string]testCase{
	"dc": delegatedCredentialTestCase{},
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
		config, err := handler.ClientConfig()
		if err != nil {
			log.Fatal(err)
			return
		}

		conn, err := tls.Dial("tcp", "server:4433", config)
		if err != nil {
			log.Fatal(err)
			return
		}
		defer conn.Close()

		if !handler.ClientConnectionHandler(conn) {
			os.Exit(-1)
		}
	} else {
		panic("Server role not implemented")
	}
}
