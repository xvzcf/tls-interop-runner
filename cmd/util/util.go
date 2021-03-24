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
    $ util -make-dc -cert-in leaf.crt -key-in leaf.key -out dc.txt
    $ util -make-ech-key -cert-in client-facing.crt -out ech_configs -key-out ech_key
    $ util -make-ech-key -cert-in client_facing.crt -out ech_configs -key-out ech_key
    $ util -process-results -path /path/to/results

    The -alg option can be passed to -make-root, -make-intermediate, and -make-dc.
    When it is not specified, a suitable one is chosen at random.

    Note: This CLI is present only to faciliate basic testing and debugging.
`

func main() {
	log.SetFlags(0)
	var (
		makeRootCert         = flag.Bool("make-root", false, "")
		makeIntermediateCert = flag.Bool("make-intermediate", false, "")
		makeDC               = flag.Bool("make-dc", false, "")
		makeECH              = flag.Bool("make-ech", false, "")
		processResults       = flag.Bool("process-results", false, "")
		help                 = flag.Bool("help", false, "")
		resultsPath          = flag.String("path", "", "")
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
	if *makeDC && (*inCertPath == "" || *outPath == "" || *inKeyPath == "") {
		log.Fatalln("ERROR: -make-dc requires -cert-in, -key-in, -out")
	}
	if *makeECH && (*hostName == "") {
		log.Fatalln("ERROR: -make-ech requires -host")
	}

	if *makeRootCert {
		keypairAlgorithm, err := utils.MakeRootCertificate(
			&utils.Config{
				Hostnames:          []string{*hostName},
				ValidFrom:          time.Now(),
				ValidFor:           365 * 25 * time.Hour,
				SignatureAlgorithm: uint16(*algorithm),
			},
			*outPath,
			*outKeyPath,
		)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err)
		}
		log.Printf("The new root certificate and key with algorithm 0x%X are at %s and %s.\n", keypairAlgorithm, *outPath, *outKeyPath)
	} else if *makeIntermediateCert {
		keypairAlgorithm, err := utils.MakeIntermediateCertificate(
			&utils.Config{
				Hostnames:          []string{*hostName},
				ValidFrom:          time.Now(),
				ValidFor:           365 * 25 * time.Hour,
				SignatureAlgorithm: uint16(*algorithm),
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
		log.Printf("The new intermediate certificate and key with algorithm 0x%X are at %s and %s.\n", keypairAlgorithm, *outPath, *outKeyPath)
	} else if *makeDC {
		keypairAlgorithm, err := utils.MakeDelegatedCredential(
			&utils.Config{
				ValidFor:           24 * time.Hour,
				SignatureAlgorithm: uint16(*algorithm),
			},
			*inCertPath,
			*inKeyPath,
			*outPath,
		)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err)
		}
		log.Printf("The new delegated credential (format: DC, privkey) with algorithm 0x%X is at \"%s\" \n", keypairAlgorithm, *outPath)
	} else if *makeECH {
		err := utils.MakeECHKey(
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
		if err != nil {
			log.Fatalf("ERROR: %s\n", err)
		}
	} else if *processResults && *resultsPath != "" {
        err := utils.ProcessTestResults(*resultsPath)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err)
		}
	} else {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
}
