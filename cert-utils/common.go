// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
    "io"
	"crypto/rand"
	"math/big"
)

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

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

type SignatureBugs struct {
	// InvalidSignature specifies that the signature in a ServerKeyExchange
	// or CertificateVerify message should be invalid.
	InvalidSignature bool

    // UseLegacySigningAlgorithm, if non-zero, is the signature algorithm
	// to use when signing in TLS 1.1 and earlier where algorithms are not
	// negotiated.
	UseLegacySigningAlgorithm signatureAlgorithm

    // BadECDSAR controls ways in which the 'r' value of an ECDSA signature
	// can be invalid.
	BadECDSAR BadValue
	BadECDSAS BadValue

    // SkipECDSACurveCheck, if true, causes all ECDSA curve checks to be
	// skipped.
	SkipECDSACurveCheck bool

    // IgnoreSignatureVersionChecks, if true, causes all signature
	// algorithms to be enabled at all TLS versions.
	IgnoreSignatureVersionChecks bool
}


// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader
	// Bugs specifies optional misbehaviour to be used for testing other
	// implementations.
	Bugs SignatureBugs
}
func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}
