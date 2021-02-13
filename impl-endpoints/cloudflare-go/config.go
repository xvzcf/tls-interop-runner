package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
)

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
