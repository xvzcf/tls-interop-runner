// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

// SPDX-FileCopyrightText: 2009 The Go Authors
// SPDX-License-Identifier: BSD-3-Clause

// This file is based on code found in
// https://boringssl.googlesource.com/boringssl/+/refs/heads/master/ssl/test/runner/

package main

import (
	"crypto/rand"
	"io"
	"log"
	"math/big"
	"time"
)

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s\n", msg, err)
	}
}

type dsaSignature struct {
	R, S *big.Int
}

type ECDSASignature dsaSignature

type signatureAlgorithm uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms
	signatureRSAPKCS1WithMD5    signatureAlgorithm = 0x0101
	signatureRSAPKCS1WithSHA1   signatureAlgorithm = 0x0201
	signatureRSAPKCS1WithSHA256 signatureAlgorithm = 0x0401
	signatureRSAPKCS1WithSHA384 signatureAlgorithm = 0x0501
	signatureRSAPKCS1WithSHA512 signatureAlgorithm = 0x0601

	// ECDSA algorithms
	signatureECDSAWithSHA1          signatureAlgorithm = 0x0203
	signatureECDSAWithP256AndSHA256 signatureAlgorithm = 0x0403
	signatureECDSAWithP384AndSHA384 signatureAlgorithm = 0x0503
	signatureECDSAWithP521AndSHA512 signatureAlgorithm = 0x0603

	// RSASSA-PSS algorithms
	signatureRSAPSSWithSHA256 signatureAlgorithm = 0x0804
	signatureRSAPSSWithSHA384 signatureAlgorithm = 0x0805
	signatureRSAPSSWithSHA512 signatureAlgorithm = 0x0806

	// EdDSA algorithms
	signatureEd25519 signatureAlgorithm = 0x0807
	signatureEd448   signatureAlgorithm = 0x0808
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
	SignatureAlgorithm signatureAlgorithm
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}
