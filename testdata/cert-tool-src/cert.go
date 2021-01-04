// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
)

func makeRootCertificate(config *Config, outPath string, outKeyPath string) {
	signer, err := getSigner(&config.Bugs, config.rand(), config.SignatureAlgorithm)
	fatalIfErr(err, "failed to get Signer")

	priv, err := signer.GenerateKey()
	fatalIfErr(err, "failed to generate private key")

	pub := priv.Public()
	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(config.rand(), serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"tls-interop-runner development CA"},
			OrganizationalUnit: []string{"tls-interop-runner"},

			// The CommonName is required by iOS to show the certificate in the
			// "Certificate Trust Settings" menu.
			// https://github.com/FiloSottile/mkcert/issues/47
			CommonName: "tls-interop-runner",
		},
		SubjectKeyId: skid[:],

		NotBefore: config.ValidFrom,
		NotAfter:  config.ValidFrom.Add(config.ValidFor),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	cert, err := x509.CreateCertificate(config.rand(), tpl, tpl, pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")

	err = ioutil.WriteFile(outKeyPath, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to write CA key")

	err = ioutil.WriteFile(outPath, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to write CA cert")

	log.Printf("Created a new root certificate.\n")
}

func makeIntermediateCertificate(config *Config, inCertPath string, inKeyPath string, outPath string, outKeyPath string) {
	signer, err := getSigner(&config.Bugs, config.rand(), config.SignatureAlgorithm)
	fatalIfErr(err, "failed to get Signer")

	priv, err := signer.GenerateKey()
	fatalIfErr(err, "failed to generate private key")

	pub := priv.Public()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(config.rand(), serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"tls-interop-runner development certificate"},
			OrganizationalUnit: []string{"tls-interop-runner"},
		},

		NotBefore: config.ValidFrom,
		NotAfter:  config.ValidFrom.Add(config.ValidFor),

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	for _, h := range config.Hostnames {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	if config.ForClient {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	if config.ForDC {
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44},
			Critical: false,
			Value:    nil,
		})
	}

	parentCertPEMBlock, err := ioutil.ReadFile(filepath.Join(inCertPath))
	fatalIfErr(err, "failed to read the input certificate")
	parentCertDERBlock, _ := pem.Decode(parentCertPEMBlock)
	if parentCertDERBlock == nil || parentCertDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read input certificate: unexpected content")
	}
	parentCert, err := x509.ParseCertificate(parentCertDERBlock.Bytes)
	fatalIfErr(err, "failed to parse input certificate")

	parentKeyPEMBlock, err := ioutil.ReadFile(filepath.Join(inKeyPath))
	fatalIfErr(err, "failed to read the key")
	parentKeyDERBlock, _ := pem.Decode(parentKeyPEMBlock)
	if parentKeyDERBlock == nil || parentKeyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the key: unexpected content")
	}
	parentKey, err := x509.ParsePKCS8PrivateKey(parentKeyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the key")

	cert, err := x509.CreateCertificate(config.rand(), tpl, parentCert, pub, parentKey)
	fatalIfErr(err, "failed to generate certificate")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode certificate key")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	if outPath == outKeyPath {
		err = ioutil.WriteFile(outKeyPath, append(certPEM, privPEM...), 0600)
		fatalIfErr(err, "failed to save certificate and key")
	} else {
		err = ioutil.WriteFile(outPath, certPEM, 0644)
		fatalIfErr(err, "failed to save certificate")
		err = ioutil.WriteFile(outKeyPath, privPEM, 0600)
		fatalIfErr(err, "failed to save certificate key")
	}
}

func makeDelegatedCredential(config *Config, parentSignConfig *Config, inCertPath string, inKeyPath string, outPath string) {
	lifetimeSecs := int64(config.ValidFor.Seconds())
	var dc []byte
	// https://tools.ietf.org/html/draft-ietf-tls-subcerts-09#section-4
	dc = append(dc, byte(lifetimeSecs>>24), byte(lifetimeSecs>>16), byte(lifetimeSecs>>8), byte(lifetimeSecs))
	dc = append(dc, byte(config.SignatureAlgorithm>>8), byte(config.SignatureAlgorithm))

	signer, err := getSigner(&config.Bugs, config.rand(), config.SignatureAlgorithm)
	fatalIfErr(err, "failed to get Signer")

	priv, err := signer.GenerateKey()
	fatalIfErr(err, "failed to generate private key")

	privPKCS8, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to marshal ECDSA Key")

	pub := priv.Public()
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	fatalIfErr(err, "failed to marshal public Key")

	dc = append(dc, byte(len(pubBytes)>>16), byte(len(pubBytes)>>8), byte(len(pubBytes)))
	dc = append(dc, pubBytes...)

	parentCertPEMBlock, err := ioutil.ReadFile(filepath.Join(inCertPath))
	fatalIfErr(err, "failed to read the input certificate")
	parentCertDERBlock, _ := pem.Decode(parentCertPEMBlock)
	if parentCertDERBlock == nil || parentCertDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the certificate: unexpected content")
	}

	parentKeyPEMBlock, err := ioutil.ReadFile(filepath.Join(inKeyPath))
	fatalIfErr(err, "failed to read the key")
	parentKeyDERBlock, _ := pem.Decode(parentKeyPEMBlock)
	if parentKeyDERBlock == nil || parentKeyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the key: unexpected content")
	}
	parentKey, err := x509.ParsePKCS8PrivateKey(parentKeyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the key")

	var parentSigAlg signatureAlgorithm

	parentPubKey := parentKey.(crypto.Signer).Public()
	switch pk := parentPubKey.(type) {
	case *ecdsa.PublicKey:
		curveName := pk.Curve.Params().Name
		if curveName == "P-256" {
			parentSigAlg = signatureECDSAWithP256AndSHA256
		} else if curveName == "P-384" {
			parentSigAlg = signatureECDSAWithP384AndSHA384
		} else if curveName == "P-521" {
			parentSigAlg = signatureECDSAWithP521AndSHA512
		} else {
			log.Fatalf("ERROR: public key unsupported\n")
		}
	default:
		log.Fatalf("ERROR: public key unsupported\n")
	}

	dc = append(dc, byte(parentSigAlg>>8), byte(parentSigAlg))

	messageToSign := make([]byte, 64, 128)
	for i := range messageToSign {
		messageToSign[i] = 0x20
	}
	if config.ForClient {
		messageToSign = append(messageToSign, []byte("TLS, client delegated credentials\x00")...)
	} else {
		messageToSign = append(messageToSign, []byte("TLS, server delegated credentials\x00")...)
	}
	messageToSign = append(messageToSign, parentCertDERBlock.Bytes...)
	messageToSign = append(messageToSign, dc...)

	parentSigner, err := getSigner(&parentSignConfig.Bugs, parentSignConfig.rand(), parentSigAlg)
	fatalIfErr(err, "failed to get Signer")

	parentSignature, err := parentSigner.SignWithKey(parentKey, messageToSign)
	fatalIfErr(err, "failed to get parent signature")

	dc = append(dc, byte(len(parentSignature)>>8), byte(len(parentSignature)))
	dc = append(dc, parentSignature...)

	dcSerialized := fmt.Sprintf("%x,%x", dc, privPKCS8)
	err = ioutil.WriteFile(outPath, []byte(dcSerialized), 0644)
	fatalIfErr(err, "failed to save DC")
	log.Printf("\nThe generated DC (format: DC, privkey) is at \"%s\" \n\n", outPath)
}
