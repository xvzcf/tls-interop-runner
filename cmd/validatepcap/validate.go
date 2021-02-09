// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
)

func validateTranscript(transcript tlsTranscript, testCase string) error {
	switch testCase {
	case "dc":
		if transcript.clientHello.version != 0x0303 {
			return errors.New("ClientHello: legacy_version is not TLS 1.2.")
		}
		if !transcript.clientHello.supportsDC {
			return errors.New("ClientHello: support for delegated credentials not indicated.")
		}
		if transcript.clientHello.serverName != "example.com" {
			return errors.New("ClientHello: SNI should specify example.com")
		}
		for _, v := range transcript.clientHello.supportedVersions {
			if v == 0x0304 {
				return nil
			}
		}
		return errors.New("ClientHello: supported_versions does not include TLS 1.3.")
	}
	return nil
}
