// Copyright 2018 The cert-tool Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This code is based on https://github.com/FiloSottile/mkcert
// and also draws from https://boringssl.googlesource.com/boringssl/+/refs/heads/master/ssl/test/runner/
// It's in very rough shape right now; more documentation and refactoring to follow.

package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/circl/hpke"
)

const usage = `Usage:

    $ util [-help] {-make-root|-make-intermediate|-make-dc} [-cert-in PATH] [-key-in PATH] [-out PATH] [-key-out PATH]

    $ util -make-root -out root.crt -key-out root.key -host root.com
    $ util -make-intermediate -cert-in parent.crt -key-in parent.key -out child.crt -key-out child.key -host example.com
    $ util -make-dc -cert-in leaf.crt -key-in leaf.key -out dc.txt
    $ util -make-ech-key -cert-in client_facing.crt -out ech_configs -key-out ech_key

    Note: This is a barebones CLI intended for basic usage/debugging.
`

func main() {
	log.SetFlags(0)
	var (
		makeRootCert         = flag.Bool("make-root", false, "")
		makeIntermediateCert = flag.Bool("make-intermediate", false, "")
		makeDC               = flag.Bool("make-dc", false, "")
		makeECH              = flag.Bool("make-ech", false, "")
		help                 = flag.Bool("help", false, "")
		inCertPath           = flag.String("cert-in", "", "")
		inKeyPath            = flag.String("key-in", "", "")
		outPath              = flag.String("out", "", "")
		outKeyPath           = flag.String("key-out", "", "")
		hostName             = flag.String("host", "", "")
	)
	flag.Parse()
	if *help {
		fmt.Print(usage)
		return
	}
	if *makeRootCert && (*outPath == "" || *outKeyPath == "" || *hostName == "") {
		log.Fatalln("ERROR: -make-root requires -out and -key-out -host")
	}
	if *makeIntermediateCert && (*inCertPath == "" || *outKeyPath == "" || *inKeyPath == "" || *outKeyPath == "" || *hostName == "") {
		log.Fatalln("ERROR: -make-intermediate requires -cert-in, -key-in, -out, -key-out, -host")
	}
	if *makeDC && (*inCertPath == "" || *outPath == "" || *inKeyPath == "") {
		log.Fatalln("ERROR: -make-dc requires -cert-in, -key-in, -out")
	}

	if *makeRootCert {
		makeRootCertificate(
			&Config{
				Hostnames:          []string{*hostName},
				ValidFrom:          time.Now(),
				ValidFor:           365 * 25 * time.Hour,
				SignatureAlgorithm: signatureECDSAWithP521AndSHA512,
			},
			*outPath,
			*outKeyPath,
		)
	} else if *makeIntermediateCert {
		makeIntermediateCertificate(
			&Config{
				Hostnames:          []string{*hostName},
				ValidFrom:          time.Now(),
				ValidFor:           365 * 25 * time.Hour,
				SignatureAlgorithm: signatureECDSAWithP256AndSHA256,
				ForDC:              true,
			},
			*inCertPath,
			*inKeyPath,
			*outPath,
			*outKeyPath,
		)
	} else if *makeDC {
		makeDelegatedCredential(
			&Config{
				ValidFor:           24 * time.Hour,
				SignatureAlgorithm: signatureECDSAWithP521AndSHA512,
			},
			&Config{},
			*inCertPath,
			*inKeyPath,
			*outPath,
		)
	} else if *makeECH {
		makeECHKey(
			ECHConfigTemplate{
				Version: ECHVersionDraft09,
				KemId:   uint16(hpke.KEM_X25519_HKDF_SHA256),
				KdfIds: []uint16{
					uint16(hpke.KDF_HKDF_SHA256),
				},
				AeadIds: []uint16{
					uint16(hpke.AEAD_AES128GCM),
				},
				MaximumNameLength: 0,
			},
			*inCertPath,
			*outPath,
			*outKeyPath,
		)
	} else {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
}
