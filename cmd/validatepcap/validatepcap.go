package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

const usage = `Usage:

    $ validatepcap [-help] {-pcap-in} {-keylog-in} {-testcase}

    Requires tshark with version >= 3.4.0
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

	tsharkPath, err := exec.LookPath("tshark")
	fatalIfErr(err, "tshark not found in PATH.")

	tsharkConfiguration, err := exec.Command(tsharkPath, "--version").Output()
	fatalIfErr(err, "Could not retrieve tshark configuration.")

	tsharkVersionLine := strings.Split(string(tsharkConfiguration), "\n")[0]
	tsharkVersionFields := strings.Split(strings.Fields(tsharkVersionLine)[2], ".")
	tsharkMajorVersion, err := strconv.Atoi(tsharkVersionFields[0])
	fatalIfErr(err, "Could not retrieve tshark major version.")

	tsharkMinorVersion, err := strconv.Atoi(tsharkVersionFields[1])
	fatalIfErr(err, "Could not retrieve tshark minor version.")

	if tsharkMajorVersion < 3 || tsharkMinorVersion < 4 {
		log.Fatalf("Requires tshark with version >= 3.4.0.")
	}

	transcript := processPcap(tsharkPath, *pcapPath, *keylogPath)

	if !isTranscriptValid(transcript, *testcase) {
		log.Printf("Testcase %s failed.\n", *testcase)
	} else {
		log.Printf("Testcase %s passed.\n", *testcase)
	}
}
