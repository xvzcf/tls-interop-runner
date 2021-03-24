// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

// SPDX-FileCopyrightText: 2009 The Go Authors
// SPDX-License-Identifier: BSD-3-Clause

// This file is based on code found in
// https://boringssl.googlesource.com/boringssl/+/refs/heads/master/ssl/test/runner/

package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
)

const (
	// RSASSA-PKCS1-v1_5 algorithms
	SignatureRSAPKCS1WithMD5    uint16 = 0x0101
	SignatureRSAPKCS1WithSHA1   uint16 = 0x0201
	SignatureRSAPKCS1WithSHA256 uint16 = 0x0401
	SignatureRSAPKCS1WithSHA384 uint16 = 0x0501
	SignatureRSAPKCS1WithSHA512 uint16 = 0x0601

	// ECDSA algorithms
	SignatureECDSAWithP256AndSHA256 uint16 = 0x0403
	SignatureECDSAWithP384AndSHA384 uint16 = 0x0503
	SignatureECDSAWithP521AndSHA512 uint16 = 0x0603

	// EdDSA algorithms
	SignatureEd25519 uint16 = 0x0807
)

const (
	SignatureTypeECDSA    uint = iota
	SignatureTypeEd25519  uint = iota
	SignatureTypeRSAPKCS1 uint = iota
)

// Signer represents an structure holding the signing information
type Signer struct {
	algorithmID   uint16
	signatureType uint
	rand          io.Reader
	hash          crypto.Hash
	priv          crypto.PrivateKey
	curve         elliptic.Curve
	rsaBits       int
}

// GenerateKey generates a public and private key pair.
func (e *Signer) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	var privK crypto.PrivateKey
	var pubK crypto.PublicKey
	var err error

	switch e.signatureType {
	case SignatureTypeECDSA:
		privK, err = ecdsa.GenerateKey(e.curve, e.rand)
		if err != nil {
			return nil, nil, err
		}
		pubK = privK.(*ecdsa.PrivateKey).Public()
	case SignatureTypeEd25519:
		pubK, privK, err = ed25519.GenerateKey(e.rand)
		if err != nil {
			return nil, nil, err
		}
	case SignatureTypeRSAPKCS1:
		privK, err = rsa.GenerateKey(e.rand, e.rsaBits)
		if err != nil {
			return nil, nil, err
		}
		pubK = privK.(*rsa.PrivateKey).Public()
	}
	e.priv = privK
	return privK, pubK, nil
}

var directSigning crypto.Hash = 0

// SignWithKey sings a message with the appropriate key. It is only used by
// delegated credentials, and only supports algorithms allowed for them.
func (e *Signer) SignWithKey(key crypto.PrivateKey, msg []byte) ([]byte, error) {
	var digest []byte
	if e.hash != directSigning {
		h := e.hash.New()
		h.Write(msg)
		digest = h.Sum(nil)
	}

	var sig []byte
	var err error
	switch sk := key.(type) {
	case *ecdsa.PrivateKey:
		opts := crypto.SignerOpts(e.hash)
		sig, err = sk.Sign(e.rand, digest, opts)
		if err != nil {
			return nil, err
		}
	case ed25519.PrivateKey:
		opts := crypto.SignerOpts(e.hash)
		sig, err = sk.Sign(e.rand, msg, opts)
		if err != nil {
			return nil, err
		}
	case rsa.PrivateKey:
		if e.signatureType == SignatureTypeRSAPKCS1 {
			opts := crypto.SignerOpts(e.hash)
			sig, err = sk.Sign(e.rand, msg, opts)
		} else {
			opts := &rsa.PSSOptions{Hash: e.hash}
			sig, err = sk.Sign(e.rand, msg, opts)
		}
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	return sig, nil
}

// TODO(claucece): as this is used beyond DCs, it needs to support all the other algos.
func getSigner(randReader io.Reader, sigAlg uint16, selectValidDCAlg bool) (*Signer, error) {
	if sigAlg == 0 { // Choose one at random
		sigAlgList := []uint16{SignatureECDSAWithP256AndSHA256,
			SignatureECDSAWithP384AndSHA384,
			SignatureECDSAWithP521AndSHA512,
			SignatureEd25519}
		if !selectValidDCAlg {
			sigAlgList = append(sigAlgList,
				[]uint16{SignatureRSAPKCS1WithMD5,
					SignatureRSAPKCS1WithSHA1,
					SignatureRSAPKCS1WithSHA256,
					SignatureRSAPKCS1WithSHA384,
					SignatureRSAPKCS1WithSHA512}...)
		}

		buf := make([]byte, 1)
		_, err := randReader.Read(buf)
		if err != nil {
			return nil, err
		}
		sigAlg = sigAlgList[int(buf[0])%len(sigAlgList)]
	}
	switch sigAlg {
	case SignatureECDSAWithP256AndSHA256:
		return &Signer{SignatureECDSAWithP256AndSHA256, SignatureTypeECDSA, randReader, crypto.SHA256, nil, elliptic.P256(), 0}, nil
	case SignatureECDSAWithP384AndSHA384:
		return &Signer{SignatureECDSAWithP384AndSHA384, SignatureTypeECDSA, randReader, crypto.SHA384, nil, elliptic.P384(), 0}, nil
	case SignatureECDSAWithP521AndSHA512:
		return &Signer{SignatureECDSAWithP521AndSHA512, SignatureTypeECDSA, randReader, crypto.SHA512, nil, elliptic.P521(), 0}, nil
	case SignatureEd25519:
		return &Signer{SignatureEd25519, SignatureTypeEd25519, randReader, directSigning, nil, nil, 0}, nil
	case SignatureRSAPKCS1WithMD5:
		return &Signer{SignatureRSAPKCS1WithMD5, SignatureTypeRSAPKCS1, randReader, crypto.MD5, nil, nil, 2048}, nil
	case SignatureRSAPKCS1WithSHA1:
		return &Signer{SignatureRSAPKCS1WithSHA1, SignatureTypeRSAPKCS1, randReader, crypto.SHA1, nil, nil, 2048}, nil
	case SignatureRSAPKCS1WithSHA256:
		return &Signer{SignatureRSAPKCS1WithSHA256, SignatureTypeRSAPKCS1, randReader, crypto.SHA1, nil, nil, 2048}, nil
	case SignatureRSAPKCS1WithSHA384:
		return &Signer{SignatureRSAPKCS1WithSHA384, SignatureTypeRSAPKCS1, randReader, crypto.SHA1, nil, nil, 3072}, nil
	case SignatureRSAPKCS1WithSHA512:
		return &Signer{SignatureRSAPKCS1WithSHA512, SignatureTypeRSAPKCS1, randReader, crypto.SHA1, nil, nil, 4096}, nil
	}

	return nil, fmt.Errorf("unsupported signature algorithm %04x", sigAlg)
}
