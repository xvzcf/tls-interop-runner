// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This code is based on https://github.com/FiloSottile/mkcert
// and also draws from https://boringssl.googlesource.com/boringssl/+/refs/heads/master/ssl/test/runner/
// It's in rough shape right now; more documentation and refactoring to follow.

package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"regexp"
    "time"

	"golang.org/x/net/idna"
)

const shortUsage = `Usage:

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".
`

const advancedUsage = `Advanced options:

    -start-date DATE, -valid-for DURATION
        Specify the certificate validity.
	-cert-in, -key-in FILE, -generate-dc, -dc-out
	    Generate delegated credential with -cert-in and -key-in to an optional -dc-out.

	-cert-out FILE, -key-out FILE, -p12-file FILE
	    Customize the output paths.

    -dc-capable
        Generate a certificate capable of issuing delegated credentials.

	-client
	    Generate a certificate for client authentication.

	-rsa
	    Generate a certificate with an RSA key (Default is ECDSA).

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -cert-out.

	-CA
	    Output the CA certificate and key storage location to CARoot
`

func main() {
	log.SetFlags(0)
	var (
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		rsaFlag     = flag.Bool("rsa", false, "")
		validFromFlag     = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
		validForFlag      = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
		clientFlag    = flag.Bool("client", false, "")
		dcCapableFlag = flag.Bool("dc-capable", false, "")
		generateDcFlag = flag.Bool("generate-dc", false, "")
		helpFlag      = flag.Bool("help", false, "")
		csrFlag       = flag.String("csr", "", "")
		certInFlag  = flag.String("cert-in", "", "")
		keyInFlag   = flag.String("key-in", "", "")
		certOutFlag  = flag.String("cert-out", "", "")
		genCAFlag  = flag.Bool("CA", false, "")
		keyOutFlag   = flag.String("key-out", "", "")
		dcOutFlag   = flag.String("dc-out", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *csrFlag != "" && (*pkcs12Flag || *rsaFlag || *clientFlag) {
		log.Fatalln("ERROR: can only combine -csr with -cert-out")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}
	if *generateDcFlag && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -generate-dc")
	}
	(&mkcert{
		csrPath: *csrFlag,
        validFrom: *validFromFlag,
        validFor: *validForFlag,
		pkcs12:  *pkcs12Flag, rsa: *rsaFlag, client: *clientFlag,
		dcCapable: *dcCapableFlag,
		genCA: *genCAFlag,
		generateDc: *generateDcFlag,
		certIn:  *certInFlag, keyIn: *keyInFlag,
		certOut:  *certOutFlag, keyOut: *keyOutFlag, p12File: *p12FileFlag,
        dcOut: *dcOutFlag,
	}).Run(flag.Args())
}

const rootName = "rootCA.pem"
const rootKeyName = "rootCA-key.pem"

type mkcert struct {
	pkcs12, rsa, client      bool
	dcCapable                  bool
	generateDc                  bool
	dcOut                  string
	keyIn, certIn string
	keyOut, certOut, p12File string
	csrPath                    string
	validFrom string
    validFor time.Duration
	caCert                     *x509.Certificate
	caKey                      crypto.PrivateKey
    CAROOT string
    genCA bool

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *mkcert) Run(args []string) {
    m.CAROOT = "certs"
    if m.genCA {
        fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
        m.newCA()
        return
    }
    m.loadCA()

	if m.csrPath != "" {
		m.makeCertFromCSR()
		return
	}

	if m.generateDc {
        m.makeDC()
        return
	}

	if len(args) == 0 {
		flag.Usage()
		return
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email", name)
		}
	}

	m.makeCert(args)
}

func (m *mkcert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
