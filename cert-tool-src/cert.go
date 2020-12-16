// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var userAndHostname string

func init() {
	u, err := user.Current()
	if err == nil {
		userAndHostname = u.Username + "@"
	}
	if h, err := os.Hostname(); err == nil {
		userAndHostname += h
	}
	if err == nil && u.Name != "" && u.Name != u.Username {
		userAndHostname += " (" + u.Name + ")"
	}
}

func (m *mkcert) makeCert(hosts []string) {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}

	priv, err := m.generateKey(false)
	fatalIfErr(err, "failed to generate certificate key")
	pub := priv.(crypto.Signer).Public()

	var notBefore time.Time
	if len(m.validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", m.validFrom)
		if err != nil {
			log.Fatalf("Failed to parse creation date: %v", err)
		}
	}

	expiration := notBefore.Add(m.validFor)

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"tls-interop-runner development certificate"},
			OrganizationalUnit: []string{userAndHostname},
		},

		NotBefore: notBefore, NotAfter: expiration,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	for _, h := range hosts {
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

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(tpl.IPAddresses) > 0 || len(tpl.DNSNames) > 0 || len(tpl.URIs) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if len(tpl.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	// IIS (the main target of PKCS #12 files), only shows the deprecated
	// Common Name in the UI. See issue #115.
	if m.pkcs12 {
		tpl.Subject.CommonName = hosts[0]
	}

	if m.dcCapable {
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44},
			Critical: false,
			Value:    nil,
		})
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, pub, m.caKey)
	fatalIfErr(err, "failed to generate certificate")

	certOut, keyOut, p12File := m.fileNames(hosts)

	if !m.pkcs12 {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		fatalIfErr(err, "failed to encode certificate key")
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

		if certOut == keyOut {
			err = ioutil.WriteFile(keyOut, append(certPEM, privPEM...), 0600)
			fatalIfErr(err, "failed to save certificate and key")
		} else {
			err = ioutil.WriteFile(certOut, certPEM, 0644)
			fatalIfErr(err, "failed to save certificate")
			err = ioutil.WriteFile(keyOut, privPEM, 0600)
			fatalIfErr(err, "failed to save certificate key")
		}
	} else {
		domainCert, _ := x509.ParseCertificate(cert)
		pfxData, err := pkcs12.Encode(rand.Reader, priv, domainCert, []*x509.Certificate{m.caCert}, "changeit")
		fatalIfErr(err, "failed to generate PKCS#12")
		err = ioutil.WriteFile(p12File, pfxData, 0644)
		fatalIfErr(err, "failed to save PKCS#12")
	}

	m.printHosts(hosts)

	if !m.pkcs12 {
		if certOut == keyOut {
			log.Printf("\nThe certificate and key are at \"%s\" \n\n", certOut)
		} else {
			log.Printf("\nThe certificate is at \"%s\" and the key at \"%s\" \n\n", certOut, keyOut)
		}
	} else {
		log.Printf("\nThe PKCS#12 bundle is at \"%s\" \n", p12File)
		log.Printf("\nThe legacy PKCS#12 encryption password is the often hardcoded default \"changeit\" \n\n")
	}

	log.Printf("It will expire on %s\n\n", expiration.Format("2 January 2006"))
}

func (m *mkcert) printHosts(hosts []string) {
	secondLvlWildcardRegexp := regexp.MustCompile(`(?i)^\*\.[0-9a-z_-]+$`)
	log.Printf("\nCreated a new certificate valid for the following names")
	for _, h := range hosts {
		log.Printf(" - %q", h)
		if secondLvlWildcardRegexp.MatchString(h) {
			log.Printf("   Warning: many browsers don't support second-level wildcards like %q", h)
		}
	}

	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") {
			log.Printf("\nReminder: X.509 wildcards only go one level deep, so this won't match a.b.%s", h[2:])
			break
		}
	}
}

func (m *mkcert) generateKey(rootCA bool) (crypto.PrivateKey, error) {
	if m.rsa {
		return rsa.GenerateKey(rand.Reader, 3072)
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (m *mkcert) fileNames(hosts []string) (certOut, keyOut, p12File string) {
	defaultName := strings.Replace(hosts[0], ":", "_", -1)
	defaultName = strings.Replace(defaultName, "*", "_wildcard", -1)
	if len(hosts) > 1 {
		defaultName += "+" + strconv.Itoa(len(hosts)-1)
	}
	if m.client {
		defaultName += "-client"
	}

	certOut = "./" + defaultName + ".pem"
	if m.certOut != "" {
		certOut = m.certOut
	}
	keyOut = "./" + defaultName + "-key.pem"
	if m.keyOut != "" {
		keyOut = m.keyOut
	}
	p12File = "./" + defaultName + ".p12"
	if m.p12File != "" {
		p12File = m.p12File
	}

	return
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")
	return serialNumber
}

func (m *mkcert) makeDC() (dc, privPKCS8 []uint8, err error) {
	var pub crypto.PublicKey
	var curve elliptic.Curve
    var expectedAlgo signatureAlgorithm
    var tlsVersion uint16

    curve = elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
		return nil, nil, err
	}
    if privPKCS8, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
		return nil, nil, err
	}
	expectedAlgo = signatureECDSAWithP256AndSHA256

	pub = &priv.PublicKey

	lifetime := 24 * time.Hour
	lifetimeSecs := int64(lifetime.Seconds())
	tlsVersion = VersionTLS13

	// https://tools.ietf.org/html/draft-ietf-tls-subcerts-09#section-4
	dc = append(dc, byte(lifetimeSecs>>24), byte(lifetimeSecs>>16), byte(lifetimeSecs>>8), byte(lifetimeSecs))
	dc = append(dc, byte(expectedAlgo>>8), byte(expectedAlgo))

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	dc = append(dc, byte(len(pubBytes)>>16), byte(len(pubBytes)>>8), byte(len(pubBytes)))
	dc = append(dc, pubBytes...)

	parentCertPEMBlock, err := ioutil.ReadFile(filepath.Join(m.certIn))
	fatalIfErr(err, "failed to read the input certificate")

	parentCertDERBlock, _ := pem.Decode(parentCertPEMBlock)
	if parentCertDERBlock == nil || parentCertDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the certificate: unexpected content")
	}
    //parentCert, err := x509.ParseCertificate(parentCertDERBlock.Bytes)
	//fatalIfErr(err, "failed to parse the certificate")

	parentKeyPEMBlock, err := ioutil.ReadFile(filepath.Join(m.keyIn))
	fatalIfErr(err, "failed to read the key")
	parentKeyDERBlock, _ := pem.Decode(parentKeyPEMBlock)
	if parentKeyDERBlock == nil || parentKeyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the key: unexpected content")
	}
    parentKey, err := x509.ParsePKCS8PrivateKey(parentKeyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the key")

    dcMessageToSign := make([]byte, 64, 128)
	for i := range dcMessageToSign {
		dcMessageToSign[i] = 0x20
	}
	dcMessageToSign = append(dcMessageToSign, []byte("TLS, server delegated credentials\x00")...)
	dcMessageToSign = append(dcMessageToSign, parentCertDERBlock.Bytes...)
	dcMessageToSign = append(dcMessageToSign, byte(lifetimeSecs>>24), byte(lifetimeSecs>>16), byte(lifetimeSecs>>8), byte(lifetimeSecs))
	dcMessageToSign = append(dcMessageToSign, byte(expectedAlgo>>8), byte(expectedAlgo))
	dcMessageToSign = append(dcMessageToSign, byte(len(pubBytes)>>16), byte(len(pubBytes)>>8), byte(len(pubBytes)))
	dcMessageToSign = append(dcMessageToSign, pubBytes...)
	dcMessageToSign = append(dcMessageToSign, byte(expectedAlgo>>8), byte(expectedAlgo))

	var dummyConfig Config
	parentSigner, err := getSigner(tlsVersion, parentKey, &dummyConfig, expectedAlgo, false /* not for verification */)
	if err != nil {
		return nil, nil, err
	}

	parentSignature, err := parentSigner.signMessage(parentKey, &dummyConfig, dcMessageToSign)
	if err != nil {
		return nil, nil, err
	}

	dc = append(dc, byte(expectedAlgo>>8), byte(expectedAlgo))
	dc = append(dc, byte(len(parentSignature)>>8), byte(len(parentSignature)))
	dc = append(dc, parentSignature...)

    dcSerialized := fmt.Sprintf("%x,%x", dc, privPKCS8)
    if m.dcOut == "" {
        m.dcOut = "dc.txt"
    }
	err = ioutil.WriteFile(m.dcOut, []byte(dcSerialized), 0644)
	fatalIfErr(err, "failed to save DC")
    log.Printf("\nThe generated DC (format: DC, privkey) is at \"%s\" \n\n", m.dcOut)

	return dc, privPKCS8, nil

}
func (m *mkcert) makeCertFromCSR() {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}

	csrPEMBytes, err := ioutil.ReadFile(m.csrPath)
	fatalIfErr(err, "failed to read the CSR")
	csrPEM, _ := pem.Decode(csrPEMBytes)
	if csrPEM == nil {
		log.Fatalln("ERROR: failed to read the CSR: unexpected content")
	}
	if csrPEM.Type != "CERTIFICATE REQUEST" &&
		csrPEM.Type != "NEW CERTIFICATE REQUEST" {
		log.Fatalln("ERROR: failed to read the CSR: expected CERTIFICATE REQUEST, got " + csrPEM.Type)
	}
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	fatalIfErr(err, "failed to parse the CSR")
	fatalIfErr(csr.CheckSignature(), "invalid CSR signature")

	expiration := time.Now().AddDate(2, 3, 0)
	tpl := &x509.Certificate{
		SerialNumber:    randomSerialNumber(),
		Subject:         csr.Subject,
		ExtraExtensions: csr.Extensions, // includes requested SANs, KUs and EKUs

		NotBefore: time.Now(), NotAfter: expiration,

		// If the CSR does not request a SAN extension, fix it up for them as
		// the Common Name field does not work in modern browsers. Otherwise,
		// this will get overridden.
		DNSNames: []string{csr.Subject.CommonName},

		// Likewise, if the CSR does not set KUs and EKUs, fix it up as Apple
		// platforms require serverAuth for TLS.
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(csr.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, csr.PublicKey, m.caKey)
	fatalIfErr(err, "failed to generate certificate")

	var hosts []string
	hosts = append(hosts, csr.DNSNames...)
	hosts = append(hosts, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	for _, uri := range csr.URIs {
		hosts = append(hosts, uri.String())
	}
	certOut, _, _ := m.fileNames(hosts)

	err = ioutil.WriteFile(certOut, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save certificate")

	m.printHosts(hosts)

	log.Printf("\nThe certificate is at \"%s\" \n\n", certOut)

	log.Printf("It will expire on %s\n\n", expiration.Format("2 January 2006"))
}

// loadCA will load or create the CA at CAROOT.
func (m *mkcert) loadCA() {
	if !pathExists(filepath.Join(m.CAROOT, rootName)) {
		m.newCA()
	}

	certPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read the CA certificate")
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	m.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")

	if !pathExists(filepath.Join(m.CAROOT, rootKeyName)) {
		return // keyless mode, where only -install works
	}

	keyPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootKeyName))
	fatalIfErr(err, "failed to read the CA key")
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
	}
	m.caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA key")
}

func (m *mkcert) newCA() {
	priv, err := m.generateKey(true)
	fatalIfErr(err, "failed to generate the CA key")
	pub := priv.(crypto.Signer).Public()

	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"tls-interop-runner development CA"},
			OrganizationalUnit: []string{userAndHostname},

			// The CommonName is required by iOS to show the certificate in the
			// "Certificate Trust Settings" menu.
			// https://github.com/FiloSottile/mkcert/issues/47
			CommonName: "tls-interop-runner " + userAndHostname,
		},
		SubjectKeyId: skid[:],

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")
	err = ioutil.WriteFile(filepath.Join(m.CAROOT, rootKeyName), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to save CA key")

	err = ioutil.WriteFile(filepath.Join(m.CAROOT, rootName), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save CA key")

	log.Printf("Created a new local CA\n")
}
