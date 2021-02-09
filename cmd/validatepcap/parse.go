// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

type clientHelloMsg struct {
	version           uint16
	supportsDC        bool
	serverName        string
	supportedVersions []uint16
}

type serverHelloMsg struct {
	version uint16
}

type tlsTranscript struct {
	clientHello clientHelloMsg
	serverHello serverHelloMsg
}

func parsePCap(tsharkPath string, pcapPath string, keylogPath string) (transcript tlsTranscript, err error) {
	rawJSON, err := exec.Command(tsharkPath,
		"-r", pcapPath,
		"-d", "tcp.port==4433,tls",
		"-2R", "tls",
		"-o", fmt.Sprintf("tls.keylog_file:%s", keylogPath),
		"-T", "ek",
		"-J", "tls",
		"-l").Output()
	if err != nil {
		return transcript, err
	}

	// rawJSON is formatted as newline-delimited JSON.
	decoder := json.NewDecoder(bytes.NewReader(rawJSON))
	for decoder.More() {
		var obj map[string]interface{}
		if err = decoder.Decode(&obj); err != nil {
			return transcript, err
		}
		// "obj" can have one of two following forms:
		// {
		//   "index": {
		//     "_index": "packets-1969-12-31",
		//     "_type": "doc"
		//   }
		// }
		//
		// or
		//
		// {
		//   "timestamp": "0981"
		//   "layers": {
		//     "frame": { ... },
		//     "ppp": { ... },
		//     ...
		//     ...
		//     "tls": { ... }
		//    }
		// }
		//
		// We ignore objects of the first form.
		if obj["layers"] == nil {
			continue
		}

		// We're only interested in the TLS layer.
		// The "tls" object is a collection of key-value
		// pairs where the values are either strings
		// or arrays of strings.
		tls := obj["layers"].(map[string]interface{})["tls"].(map[string]interface{})

		// If "tls_tls_handshake_type" is an array
		// of strings, then the tls object contains
		// key-value pairs for multiple TLS messages.
		//
		// We first take stock of the types of TLS messages
		// present before parsing the messages out.
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
			err = parseOutClientHello(tls, &transcript)
			if err != nil {
				return transcript, err
			}

		} else if messageTypes["2"] {
			err = parseOutServerHello(tls, &transcript)
			if err != nil {
				return transcript, err
			}
		}
	}

	return transcript, err
}

func parseOutClientHello(raw map[string]interface{}, transcript *tlsTranscript) error {
	version, err := strconv.ParseUint(raw["tls_tls_handshake_version"].(string), 0, 16)
	if err != nil {
		return err
	}
	transcript.clientHello.version = uint16(version)

	transcript.clientHello.serverName = raw["tls_tls_handshake_extensions_server_name"].(string)

	for _, val := range raw["tls_tls_handshake_extension_type"].([]interface{}) {
		if val == "34" {
			transcript.clientHello.supportsDC = true
		}
	}

	for _, val := range raw["tls_tls_handshake_extensions_supported_version"].([]interface{}) {
		version, err := strconv.ParseUint(val.(string), 0, 16)
		if err != nil {
			return err
		}
		transcript.clientHello.supportedVersions = append(transcript.clientHello.supportedVersions, uint16(version))
	}
	return nil
}

func parseOutServerHello(raw map[string]interface{}, transcript *tlsTranscript) error {
	version, err := strconv.ParseUint(raw["tls_tls_handshake_version"].(string), 0, 16)
	if err != nil {
		return err
	}
	transcript.serverHello.version = uint16(version)

	return nil
}
