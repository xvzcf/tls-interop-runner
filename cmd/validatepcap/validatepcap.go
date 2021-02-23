// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/xvzcf/tls-interop-runner/internal/pcap"
)

const usage = `Usage:

    $ validatepcap [-help] {-pcap-in} {-keylog-in} {-testcase}

    Requires tshark with version >= 3.2.0 to be in the PATH
`

func main() {
	log.SetFlags(0)
	var (
		pcapPath   = flag.String("pcap-in", "", "")
		keylogPath = flag.String("keylog-in", "", "")
		testcase   = flag.String("testcase", "", "")
		help       = flag.Bool("help", false, "")
	)

	flag.Parse()
	if *help || *pcapPath == "" || *keylogPath == "" || *testcase == "" {
		fmt.Print(usage)
		return
	}

	err := pcap.FindTshark()
	if err != nil {
		log.Fatalf("ERROR: Tshark not found: %s\n", err)
	}

	transcript, err := pcap.Parse(*pcapPath, *keylogPath)
	if err != nil {
		log.Fatalf("ERROR: Could not parse pcap: %s\n", err)
	}

	err = pcap.Validate(transcript, *testcase)
	if err != nil {
		log.Fatalf("Testcase %s failed: %s", *testcase, err)
	} else {
		fmt.Printf("Testcase %s passed.\n", *testcase)
	}

}
