// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

type ECDSASigner struct {
	bugs  *CertificateBugs
	curve elliptic.Curve
	hash  crypto.Hash
	priv  *ecdsa.PrivateKey
	rand  io.Reader
}

func maybeCorruptECDSAValue(n *big.Int, typeOfCorruption BadValue, limit *big.Int) *big.Int {
	switch typeOfCorruption {
	case BadValueNone:
		return n
	case BadValueNegative:
		return new(big.Int).Neg(n)
	case BadValueZero:
		return big.NewInt(0)
	case BadValueLimit:
		return limit
	case BadValueLarge:
		bad := new(big.Int).Set(limit)
		return bad.Lsh(bad, 20)
	default:
		panic("unknown BadValue type")
	}
}

func (e *ECDSASigner) Public() *ecdsa.PublicKey {
	return &e.priv.PublicKey
}

// GenerateKey generates a public and private key pair.
func (e *ECDSASigner) GenerateKey() (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(e.curve, e.rand)
	e.priv = priv
	return priv, err
}

func (e *ECDSASigner) SignWithKey(key crypto.PrivateKey, msg []byte) ([]byte, error) {
	ecdsaKey, _ := key.(*ecdsa.PrivateKey)

	h := e.hash.New()
	h.Write(msg)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(e.rand, ecdsaKey, digest)
	fatalIfErr(err, "failed to sign ECDHE parameters")

	order := ecdsaKey.Curve.Params().N
	r = maybeCorruptECDSAValue(r, e.bugs.BadECDSAR, order)
	s = maybeCorruptECDSAValue(s, e.bugs.BadECDSAS, order)
	return asn1.Marshal(ECDSASignature{r, s})
}

func (e *ECDSASigner) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	h := e.hash.New()
	h.Write(msg)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(e.rand, e.priv, digest)
	fatalIfErr(err, "failed to sign ECDHE parameters")

	order := e.priv.Curve.Params().N
	r = maybeCorruptECDSAValue(r, e.bugs.BadECDSAR, order)
	s = maybeCorruptECDSAValue(s, e.bugs.BadECDSAS, order)
	return asn1.Marshal(ECDSASignature{r, s})
}

func getSigner(bugs *CertificateBugs, rand io.Reader, sigAlg signatureAlgorithm) (*ECDSASigner, error) {
	switch sigAlg {
	case signatureECDSAWithSHA1:
		return &ECDSASigner{bugs, nil, crypto.SHA1, nil, rand}, nil
	case signatureECDSAWithP256AndSHA256:
		return &ECDSASigner{bugs, elliptic.P256(), crypto.SHA256, nil, rand}, nil
	case signatureECDSAWithP384AndSHA384:
		return &ECDSASigner{bugs, elliptic.P384(), crypto.SHA384, nil, rand}, nil
	case signatureECDSAWithP521AndSHA512:
		return &ECDSASigner{bugs, elliptic.P521(), crypto.SHA512, nil, rand}, nil
	}

	return nil, fmt.Errorf("unsupported signature algorithm %04x", sigAlg)
}
