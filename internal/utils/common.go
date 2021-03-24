// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

// SPDX-FileCopyrightText: 2009 The Go Authors
// SPDX-License-Identifier: BSD-3-Clause

// This file is based on code found in
// https://boringssl.googlesource.com/boringssl/+/refs/heads/master/ssl/test/runner/

package utils

import (
	"crypto/rand"
	"io"
	"time"
)

// Used to configure x509 certificates and DCs.
type Config struct {
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader

	Hostnames []string

	ValidFrom time.Time
	ValidFor  time.Duration

	ForClient bool
	ForDC     bool

	// SignatureAlgorithm defines the signature algorithm for certificates or delegated credentials
	SignatureAlgorithm uint16
}

func (c *Config) rand() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}
