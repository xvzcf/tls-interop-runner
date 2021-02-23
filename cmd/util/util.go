// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/xvzcf/tls-interop-runner/internal/utils"
)

const usage = `Usage:

    $ util [-help] {-make-root|-make-intermediate|-make-dc} [-cert-in PATH] [-key-in PATH] [-out PATH] [-key-out PATH]

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

	var err error
	if *makeRootCert {
		err = utils.MakeRootCertificate(
			&utils.Config{
				Hostnames:          []string{*hostName},
				ValidFrom:          time.Now(),
				ValidFor:           365 * 25 * time.Hour,
				SignatureAlgorithm: utils.SignatureECDSAWithP521AndSHA512,
			},
			*outPath,
			*outKeyPath,
		)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err)
		}
		log.Printf("Created a new root certificate at %s.\n", *outPath)
		log.Printf("Created a new root key at %s.\n", *outKeyPath)
	} else if *makeIntermediateCert {
		err = utils.MakeIntermediateCertificate(
			&utils.Config{
				Hostnames:          []string{*hostName},
				ValidFrom:          time.Now(),
				ValidFor:           365 * 25 * time.Hour,
				SignatureAlgorithm: utils.SignatureECDSAWithP256AndSHA256,
				ForDC:              true,
			},
			*inCertPath,
			*inKeyPath,
			*outPath,
			*outKeyPath,
		)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err)
		}
		log.Printf("Created a new intermediate certificate at %s.\n", *outPath)
		log.Printf("Created a new intermediate key at %s.\n", *outKeyPath)
	} else if *makeDC {
		err = utils.MakeDelegatedCredential(
			&utils.Config{
				ValidFor:           24 * time.Hour,
				SignatureAlgorithm: uint16(*algorithm),
			},
			&utils.Config{},
			*inCertPath,
			*inKeyPath,
			*outPath,
		)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err)
		}
		log.Printf("\nThe generated DC (format: DC, privkey) using algorithm %x is at \"%s\" \n\n", *algorithm, *outPath)
	} else if *makeECH {
		err = utils.MakeECHKey(
			utils.ECHConfigTemplate{
				PublicName: *hostName,
				Version:    utils.ECHVersionDraft09,
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
