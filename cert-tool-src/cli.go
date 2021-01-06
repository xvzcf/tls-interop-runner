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

	$ cert-tool [-help] {-make-root|-make-intermediate|-make-dc} [-cert-in PATH] [-key-in PATH] [-out PATH] [-key-out PATH]

    $ cert-tool -make-root -out tmp/CA.crt -key-out tmp/CA.key
    $ cert-tool -make-intermediate -cert-in tmp/CA.crt -key-in tmp/CA.key -out tmp/int.crt -key-out tmp/int.key
    $ cert-tool -make-dc -cert-in tmp/int.crt -key-in tmp/int.key -out tmp/dc.txt
    $ cert-tool -make-ech-key -cert-in tmp/int.crt -out tmp/ech_configs.txt -key-out tmp/ech_key.txt

    Note: This is a barebones CLI intended for basic usage/debugging.
`

func main() {
	log.SetFlags(0)
	var (
		makeRootCertFlag         = flag.Bool("make-root", false, "")
		makeIntermediateCertFlag = flag.Bool("make-intermediate", false, "")
		makeDCFlag               = flag.Bool("make-dc", false, "")
		makeECHKeyFlag           = flag.Bool("make-ech-key", false, "")
		helpFlag                 = flag.Bool("help", false, "")
		certInFlag               = flag.String("cert-in", "", "")
		keyInFlag                = flag.String("key-in", "", "")
		outFlag                  = flag.String("out", "", "")
		keyOutFlag               = flag.String("key-out", "", "")
	)
	flag.Parse()
	if *helpFlag {
		fmt.Print(usage)
		return
	}
	if *makeRootCertFlag && (*outFlag == "" || *keyOutFlag == "") {
		log.Fatalln("ERROR: -make-root requires -out and -key-out")
	}
	if *makeIntermediateCertFlag && (*certInFlag == "" || *outFlag == "" || *keyInFlag == "" || *keyOutFlag == "") {
		log.Fatalln("ERROR: -make-intermediate requires -cert-in, -key-in, -out, -key-out")
	}
	if *makeDCFlag && (*certInFlag == "" || *outFlag == "" || *keyInFlag == "") {
		log.Fatalln("ERROR: -make-dc requires -cert-in, -key-in, -out")
	}
	(&certTool{
		makeRootCert:         *makeRootCertFlag,
		makeIntermediateCert: *makeIntermediateCertFlag,
		makeDC:               *makeDCFlag,
		makeECHKey:           *makeECHKeyFlag,
		inCertPath:           *certInFlag, inKeyPath: *keyInFlag,
		outPath: *outFlag, outKeyPath: *keyOutFlag,
	}).Run()
}

type certTool struct {
	makeRootCert          bool
	makeIntermediateCert  bool
	makeDC                bool
	makeECHKey            bool
	inCertPath, inKeyPath string
	outPath, outKeyPath   string
}

func (ct *certTool) Run() {
	if ct.makeRootCert {
		makeRootCertificate(&Config{
			Hostnames:          []string{"server"},
			ValidFrom:          time.Now(),
			ValidFor:           365 * 25 * time.Hour,
			SignatureAlgorithm: signatureECDSAWithP521AndSHA512,
		},
			ct.outPath, ct.outKeyPath)
		return
	} else if ct.makeIntermediateCert {
		makeIntermediateCertificate(&Config{
			Hostnames:          []string{"server"},
			ValidFrom:          time.Now(),
			ValidFor:           365 * 25 * time.Hour,
			SignatureAlgorithm: signatureECDSAWithP256AndSHA256,
			ForDC:              true,
		},
			ct.inCertPath, ct.inKeyPath,
			ct.outPath, ct.outKeyPath)
		return
	} else if ct.makeDC {
		makeDelegatedCredential(&Config{
			ValidFor:           24 * time.Hour,
			SignatureAlgorithm: signatureECDSAWithP521AndSHA512,
		},
			&Config{},
			ct.inCertPath, ct.inKeyPath, ct.outPath)
		return
	} else if ct.makeECHKey {
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
			ct.inCertPath,
			ct.outPath,
			ct.outKeyPath,
		)
	} else {
		fmt.Fprint(flag.CommandLine.Output(), usage)
		return
	}
}
