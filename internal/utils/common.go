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
	"math/big"
	"time"
)

type dsaSignature struct {
	R, S *big.Int
}

type ECDSASignature dsaSignature

const (
	// RSASSA-PKCS1-v1_5 algorithms
	SignatureRSAPKCS1WithMD5    uint16 = 0x0101
	SignatureRSAPKCS1WithSHA1   uint16 = 0x0201
	SignatureRSAPKCS1WithSHA256 uint16 = 0x0401
	SignatureRSAPKCS1WithSHA384 uint16 = 0x0501
	SignatureRSAPKCS1WithSHA512 uint16 = 0x0601

	// ECDSA algorithms
	SignatureECDSAWithSHA1          uint16 = 0x0203
	SignatureECDSAWithP256AndSHA256 uint16 = 0x0403
	SignatureECDSAWithP384AndSHA384 uint16 = 0x0503
	SignatureECDSAWithP521AndSHA512 uint16 = 0x0603

	// RSASSA-PSS algorithms
	SignatureRSAPSSWithSHA256 uint16 = 0x0804
	SignatureRSAPSSWithSHA384 uint16 = 0x0805
	SignatureRSAPSSWithSHA512 uint16 = 0x0806

	// EdDSA algorithms
	SignatureEd25519 uint16 = 0x0807
	SignatureEd448   uint16 = 0x0808
)

type BadValue int

const (
	BadValueNone BadValue = iota
	BadValueNegative
	BadValueZero
	BadValueLimit
	BadValueLarge
	NumBadValues
)

type CertificateBugs struct {
	// BadECDSAR controls ways in which the 'r' value of an ECDSA signature
	// can be invalid.
	BadECDSAR BadValue
	BadECDSAS BadValue
}

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

	// Bugs specifies optional misbehaviour to be used for testing other
	// implementations.
	Bugs CertificateBugs

	// SignatureAlgorithm defines the signature algorithm for certificates or delegated credentials
	SignatureAlgorithm uint16
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}
