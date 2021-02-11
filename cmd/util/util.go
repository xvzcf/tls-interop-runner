// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/circl/hpke"
)

const usage = `Usage:

    $ util [-help] {-make-root|-make-intermediate|-make-dc|-make-dcvectors} [-cert-in PATH] [-key-in PATH] [-out PATH] [-key-out PATH]

    $ util -make-root -out root.crt -key-out root.key -host root.com
    $ util -make-intermediate -cert-in parent.crt -key-in parent.key -out child.crt -key-out child.key -host example.com
    $ util -make-dc -cert-in leaf.crt -key-in leaf.key -alg algorithm -out dc.txt
    $ util -make-ech-key -cert-in client-facing.crt -out ech_configs -key-out ech_key
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
		algorithm            = flag.Uint("alg", 0, "")
	)
	flag.Parse()
	if *help {
		fmt.Print(usage)
		return
	}
	if *makeRootCert && (*outPath == "" || *outKeyPath == "" || *hostName == "") {
		log.Fatalln("ERROR: -make-root requires -out and -key-out -host")
	}
	if *makeIntermediateCert && (*inCertPath == "" || *outKeyPath == "" || *inKeyPath == "" || *outPath == "" || *hostName == "") {
		log.Fatalln("ERROR: -make-intermediate requires -cert-in, -key-in, -out, -key-out, -host")
	}
	if *makeDC && (*inCertPath == "" || *outPath == "" || *inKeyPath == "" || *algorithm == 0) {
		log.Fatalln("ERROR: -make-dc requires -cert-in, -key-in, -alg, -out")
	}
	if *makeECH && (*hostName == "") {
		log.Fatalln("ERROR: -make-ech requires -host")
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
				SignatureAlgorithm: signatureAlgorithm(*algorithm),
			},
			&Config{},
			*inCertPath,
			*inKeyPath,
			*outPath,
		)
	} else if *makeECH {
		makeECHKey(
			ECHConfigTemplate{
				PublicName: *hostName,
				Version:    ECHVersionDraft09,
				KemId:      uint16(hpke.KEM_X25519_HKDF_SHA256),
				KdfIds: []uint16{
					uint16(hpke.KDF_HKDF_SHA256),
				},
				AeadIds: []uint16{
					uint16(hpke.AEAD_AES128GCM),
				},
				MaximumNameLength: 0,
			},
			*outPath,
			*outKeyPath,
		)
	} else {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
}
