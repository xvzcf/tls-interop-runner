// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

// SPDX-FileCopyrightText: 2018 The mkcert Authors
// SPDX-License-Identifier: BSD-3-Clause

// SPDX-FileCopyrightText: 2009 The Go Authors
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
)

// TODO(xvzcf): When passed to x509.CreateCertificate, RSA keys will result in
// an RSA-PKCS1 certificate being generated since we have no control over how
// priv.(*crypto.Signer).Sign() is called in that function. This means we currently
// cannot support RSA-PSS. x509.CreateCertificate also makes it hard to do
// certificate fuzzing.
// The solution might just be to reproduce the implementation of
// x509.CreateCertificate here with appropriate modifications.

// MakeRootCertificate is based on code found in https://github.com/FiloSottile/mkcert
func MakeRootCertificate(config *Config, outPath string, outKeyPath string) (uint16, error) {
	signer, err := getSigner(config.rand(), config.SignatureAlgorithm, false)
	if err != nil {
		return 0, err
	}

	priv, pub, err := signer.GenerateKey()
	if err != nil {
		return 0, err
	}

	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return 0, err
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return 0, err
	}

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(config.rand(), serialNumberLimit)
	if err != nil {
		return 0, err
	}

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
	if err != nil {
		return 0, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return 0, err
	}

	err = ioutil.WriteFile(outKeyPath, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600)
	if err != nil {
		return 0, err
	}

	err = ioutil.WriteFile(outPath, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	if err != nil {
		return 0, err
	}

	return signer.algorithmID, nil
}

// MakeIntermediateCertificate is based on code found in https://github.com/FiloSottile/mkcert
func MakeIntermediateCertificate(config *Config, inCertPath string, inKeyPath string, outPath string, outKeyPath string) (uint16, error) {
	signer, err := getSigner(config.rand(), config.SignatureAlgorithm, config.ForDC)
	if err != nil {
		return 0, err
	}

	priv, pub, err := signer.GenerateKey()
	if err != nil {
		return 0, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(config.rand(), serialNumberLimit)
	if err != nil {
		return 0, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"tls-interop-runner development certificate"},
			OrganizationalUnit: []string{outPath},
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
	if err != nil {
		return 0, err
	}
	parentCertDERBlock, _ := pem.Decode(parentCertPEMBlock)
	if parentCertDERBlock == nil || parentCertDERBlock.Type != "CERTIFICATE" {
		return 0, errors.New("failed to read input certificate: unexpected content")
	}
	parentCert, err := x509.ParseCertificate(parentCertDERBlock.Bytes)
	if err != nil {
		return 0, err
	}

	parentKeyPEMBlock, err := ioutil.ReadFile(filepath.Join(inKeyPath))
	if err != nil {
		return 0, err
	}
	parentKeyDERBlock, _ := pem.Decode(parentKeyPEMBlock)
	if parentKeyDERBlock == nil || parentKeyDERBlock.Type != "PRIVATE KEY" {
		return 0, errors.New("failed to read input key: unexpected content")
	}
	parentKey, err := x509.ParsePKCS8PrivateKey(parentKeyDERBlock.Bytes)
	if err != nil {
		return 0, err
	}

	cert, err := x509.CreateCertificate(config.rand(), tpl, parentCert, pub, parentKey)
	if err != nil {
		return 0, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return 0, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	if outPath == outKeyPath {
		err = ioutil.WriteFile(outKeyPath, append(certPEM, privPEM...), 0600)
		if err != nil {
			return 0, err
		}
	} else {
		err = ioutil.WriteFile(outPath, certPEM, 0644)
		if err != nil {
			return 0, err
		}

		err = ioutil.WriteFile(outKeyPath, privPEM, 0600)
		if err != nil {
			return 0, err
		}
	}
	return signer.algorithmID, nil
}

// MakeDelegatedCredential is based on code found in https://boringssl.googlesource.com/boringssl/+/refs/heads/master/ssl/test/runner/
// It generates a delegated credential for the party that asks for it
func MakeDelegatedCredential(config *Config, inCertPath string, inKeyPath string, outPath string) (uint16, error) {
	lifetimeSecs := int64(config.ValidFor.Seconds())
	var dc []byte
	// https://tools.ietf.org/html/draft-ietf-tls-subcerts-09#section-4
	dc = append(dc, byte(lifetimeSecs>>24), byte(lifetimeSecs>>16), byte(lifetimeSecs>>8), byte(lifetimeSecs))
	dc = append(dc, byte(config.SignatureAlgorithm>>8), byte(config.SignatureAlgorithm))

	signer, err := getSigner(config.rand(), config.SignatureAlgorithm, true)
	if err != nil {
		return 0, err
	}

	priv, pub, err := signer.GenerateKey()
	if err != nil {
		return 0, err
	}

	privPKCS8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return 0, err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return 0, err
	}

	dc = append(dc, byte(len(pubBytes)>>16), byte(len(pubBytes)>>8), byte(len(pubBytes)))
	dc = append(dc, pubBytes...)

	parentCertPEMBlock, err := ioutil.ReadFile(filepath.Join(inCertPath))
	if err != nil {
		return 0, err
	}
	parentCertDERBlock, _ := pem.Decode(parentCertPEMBlock)
	if parentCertDERBlock == nil || parentCertDERBlock.Type != "CERTIFICATE" {
		return 0, errors.New("failed to read the certificate: unexpected content")
	}

	parentKeyPEMBlock, err := ioutil.ReadFile(filepath.Join(inKeyPath))
	if err != nil {
		return 0, err
	}
	parentKeyDERBlock, _ := pem.Decode(parentKeyPEMBlock)
	if parentKeyDERBlock == nil || parentKeyDERBlock.Type != "PRIVATE KEY" {
		return 0, errors.New("failed to read the key: unexpected content")
	}
	parentKey, err := x509.ParsePKCS8PrivateKey(parentKeyDERBlock.Bytes)
	if err != nil {
		return 0, err
	}

	var parentSigAlg uint16
	parentPubKey := parentKey.(crypto.Signer).Public()
	switch pk := parentPubKey.(type) {
	case *ecdsa.PublicKey:
		curveName := pk.Curve.Params().Name
		if curveName == "P-256" {
			parentSigAlg = SignatureECDSAWithP256AndSHA256
		} else if curveName == "P-384" {
			parentSigAlg = SignatureECDSAWithP384AndSHA384
		} else if curveName == "P-521" {
			parentSigAlg = SignatureECDSAWithP521AndSHA512
		} else {
			return 0, errors.New("public key unsupported\n")
		}
	case ed25519.PublicKey:
		parentSigAlg = SignatureEd25519
	case rsa.PublicKey:
		bits := parentKey.(rsa.PrivateKey).N.BitLen()
		if bits == 2048 {
			parentSigAlg = SignatureRSAPKCS1WithSHA256
		} else if bits == 3072 {
			parentSigAlg = SignatureRSAPKCS1WithSHA384
		} else if bits == 4096 {
			parentSigAlg = SignatureRSAPKCS1WithSHA512
		} else {
			return 0, errors.New("error parsing RSA key.")
		}
	default:
		return 0, errors.New("public key unsupported\n")
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

	parentSigner, err := getSigner(config.rand(), parentSigAlg, false)
	if err != nil {
		return 0, err
	}

	parentSignature, err := parentSigner.SignWithKey(parentKey, messageToSign)
	if err != nil {
		return 0, err
	}

	dc = append(dc, byte(len(parentSignature)>>8), byte(len(parentSignature)))
	dc = append(dc, parentSignature...)

	dcSerialized := fmt.Sprintf("%x,%x", dc, privPKCS8)
	err = ioutil.WriteFile(outPath, []byte(dcSerialized), 0644)
	if err != nil {
		return 0, err
	}
	return signer.algorithmID, nil
}

// MakeECHKey generates an ECH config and corresponding key, writing the key to
// outKeyPath and the config to outPath. The config is encoded as an ECHConfigs
// structure as specified by draft-ietf-tls-esni-09 (i.e., it is prefixed by
// 16-bit integer that encodes its length). This is the format as it is consumed
// by the client.
func MakeECHKey(template ECHConfigTemplate, outPath, outKeyPath string) error {
	// Ensure that the public name can be used as the SNI.
	if !isDomainName(template.PublicName) {
		return fmt.Errorf("'%s' is not a fully qualified domain name", template.PublicName)
	}

	// Generate ECH config and key.
	key, err := GenerateECHKey(template)
	if err != nil {
		return err
	}

	// Write the key to disk.
	outKey, err := os.OpenFile(outKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outKey.Close()
	outKeyEncoder := base64.NewEncoder(base64.StdEncoding, outKey)
	defer outKeyEncoder.Close()
	_, err = outKeyEncoder.Write(key.Marshal())
	if err != nil {
		return err
	}

	// Write the config to disk.
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	outEncoder := base64.NewEncoder(base64.StdEncoding, out)
	defer outEncoder.Close()
	_, err = outEncoder.Write(MarshalECHConfigs([]ECHKey{*key}))
	if err != nil {
		return err
	}
	return nil
}

// isDomainName checks if a string is a presentation-format domain name
// (currently restricted to hostname-compatible "preferred name" LDH labels and
// SRV-like "underscore labels"; see golang.org/issue/12421).
//
// This was copied verbatim from src/net/dnsclient.go in the
// Go standard library.
func isDomainName(s string) bool {
	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	nonNumeric := false // true once we've seen a letter or hyphen
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return nonNumeric
}
