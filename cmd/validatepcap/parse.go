package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

type ClientHello struct {
	version           uint16
	supportsDC        bool
	serverName        string
	supportedVersions []uint16
}

type ServerHello struct {
	version uint16
}

type Transcript struct {
	clientHello ClientHello
	serverHello ServerHello
}

func parseOutClientHello(raw map[string]interface{}, transcript *Transcript) {
	version, err := strconv.ParseUint(raw["tls_tls_handshake_version"].(string), 0, 16)
	fatalIfErr(err, "Could not convert from string to uint16.")
	transcript.clientHello.version = uint16(version)

	transcript.clientHello.serverName = raw["tls_tls_handshake_extensions_server_name"].(string)

	for _, val := range raw["tls_tls_handshake_extension_type"].([]interface{}) {
		if val == "34" {
			transcript.clientHello.supportsDC = true
		}
	}

	for _, val := range raw["tls_tls_handshake_extensions_supported_version"].([]interface{}) {
		version, err := strconv.ParseUint(val.(string), 0, 16)
		fatalIfErr(err, "Could not convert from string to uint16.")

		transcript.clientHello.supportedVersions = append(transcript.clientHello.supportedVersions, uint16(version))
	}
}

func parseOutServerHello(raw map[string]interface{}, transcript *Transcript) {
	version, err := strconv.ParseUint(raw["tls_tls_handshake_version"].(string), 0, 16)
	fatalIfErr(err, "Could not convert from string to uint16.")

	transcript.serverHello.version = uint16(version)
}

func processPcap(tsharkPath string, pcapPath string, keylogPath string) Transcript {
	rawJSON, err := exec.Command(tsharkPath,
		"-r", pcapPath,
		"-d", "tcp.port==4433,tls",
		"-2R", "tls",
		"-o", fmt.Sprintf("tls.keylog_file:%s", keylogPath),
		"-T", "ek",
		"-J", "tls",
		"-l").Output()
	fatalIfErr(err, "Could not convert PCAP to JSON.")

	transcript := Transcript{}

	decoder := json.NewDecoder(bytes.NewReader(rawJSON))
	for decoder.More() {
		var obj map[string]interface{}
		err := decoder.Decode(&obj)
		fatalIfErr(err, "Could not decode JSON")
		if obj["layers"] == nil {
			continue
		}

		tls := obj["layers"].(map[string]interface{})["tls"].(map[string]interface{})

		messageTypes := map[string]bool{}
		switch value := tls["tls_tls_handshake_type"].(type) {
		case string:
			messageTypes[value] = true
		case []interface{}:
			for _, messageType := range value {
				messageTypes[messageType.(string)] = true
			}
		}

		if messageTypes["1"] {
			parseOutClientHello(tls, &transcript)
		} else if messageTypes["2"] {
			parseOutServerHello(tls, &transcript)
		}
	}

	return transcript
}
