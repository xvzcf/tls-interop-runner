package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
)

const usage = `Usage:

    $ runner [-help] {[-ci-mode] | [-client STRING] [-server STRING] [-testcase STRING]}

    $ runner -ci-mode runs all possible combinations of tests
    $ runner -client=boringssl -server=cloudflare-go -testcase=dc runs just the dc test with the boringssl client and cloudflare-go server
`

var testInputsDir = path.Join("generated", "test-inputs")
var testOutputsDir = path.Join("generated", "test-outputs")

var CIModeOutputDir = path.Join("generated", "ci")

func main() {
	log.SetFlags(0)
	var (
		CIMode       = flag.Bool("ci-mode", false, "")
		clientName   = flag.String("client", "", "")
		serverName   = flag.String("server", "", "")
		testcaseName = flag.String("testcase", "", "")
		help         = flag.Bool("help", false, "")
	)
	flag.Parse()
	if *help {
		fmt.Print(usage)
	} else if *CIMode {
		var clients []endpoint
		var servers []endpoint
		for _, e := range endpoints {
			if e.client && !e.regression {
				clients = append(clients, e)
			}
			if e.server && !e.regression {
				servers = append(servers, e)
			}
		}
		os.RemoveAll(CIModeOutputDir)
		os.MkdirAll(CIModeOutputDir, os.ModePerm)
		for name, t := range testcases {
			err := t.generateInputs()
			if err != nil {
				log.Fatalf("Error generating test inputs for testcase %s: %s", name, err)
			}
			for _, client := range clients {
				os.MkdirAll(path.Join(CIModeOutputDir, client.name), os.ModePerm)
				for _, server := range servers {
					os.MkdirAll(path.Join(CIModeOutputDir, client.name, server.name), os.ModePerm)
					fmt.Printf("client=%s,server=%s,testcase=%s,", client.name, server.name, name)
					err = t.run(client, server)
					if err != nil {
						log.Printf("Failure,run(): %s.\n", err)
						continue
					}
					err = t.verify()
					if err != nil {
						log.Printf("Failure,verify(): %s.\n", err)
						continue
					}
					log.Printf("Success")
					err = os.Rename(testOutputsDir, path.Join(CIModeOutputDir, client.name, server.name, name))
					if err != nil {
						log.Printf("Error renaming: %s.", err)
					}
				}
			}
		}
	} else if *clientName != "" && *serverName != "" && *testcaseName != "" {
		var client, server endpoint
		for _, e := range endpoints {
			if e.name == *clientName {
				if !e.client {
					log.Fatalf("%s cannot be run as a client.", *clientName)
				}
				client = e
			}
			if e.name == *serverName {
				if !e.server {
					log.Fatalf("%s cannot be run as a server.", *serverName)
				}
				server = e
			}
		}
		if t, ok := testcases[*testcaseName]; ok {
			err := t.generateInputs()
			if err != nil {
				log.Fatalf("Failure,setup(): %s.\n", err)
			}
			err = t.run(client, server)
			if err != nil {
				log.Fatalf("Failure,run(): %s.\n", err)
			}
			err = t.verify()
			if err != nil {
				log.Fatalf("Failure,verify(): %s.\n", err)
			}
			log.Printf("Success\n")
		} else {
			log.Printf("Testcase %s not found.\n", *testcaseName)
		}
	} else {
		fmt.Print(usage)
	}
}
