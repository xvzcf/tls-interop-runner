// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const usage = `Usage:

    $ runner [--help] --client=STRING --server=STRING {--testcase=STRING|--everything} [--build] [--verbose]

    $ runner --client=boringssl --server=cloudflare-go --build builds boringssl as a client and cloudflare-go as a server (and all their dependent services)
    $ runner --client=boringssl --server=cloudflare-go --testcase=dc [--build] (rebuilds the endpoints, their dependencies, then) runs just the dc test with boringssl as client and cloudflare-go as server
    $ runner --client=boringssl --server=cloudflare-go --everything [--build] (rebuilds the endpoints, their dependencies, then) runs all testcases with boringssl as client and cloudflare-go as server
    $ runner -process-results -path /path/to/results
`

var generatedDir = "generated"
var testInputsDir = filepath.Join(generatedDir, "test-inputs")
var testOutputsDir = filepath.Join(generatedDir, "test-outputs")

func main() {
	var (
		clientName           = flag.String("client", "", "")
		serverName           = flag.String("server", "", "")
		testcaseName         = flag.String("testcase", "", "")
		buildEndpoints       = flag.Bool("build", false, "")
		runAllTests          = flag.Bool("everything", false, "")
		listClients          = flag.Bool("list-clients", false, "")
		listInteropServers   = flag.Bool("list-servers", false, "")
		listInteropEndpoints = flag.Bool("list-endpoints", false, "")
		verbose              = flag.Bool("verbose", false, "")
		processResults       = flag.Bool("process-results", false, "")
		resultsPath          = flag.String("path", "", "")
		help                 = flag.Bool("help", false, "")
	)
	flag.Parse()

	if *help {
		fmt.Print(usage)
	} else if *listClients {
		jsonOut, _ := json.Marshal(getClients())
		fmt.Print(string(jsonOut))
	} else if *listInteropServers {
		jsonOut, _ := json.Marshal(getServers())
		fmt.Print(string(jsonOut))
	} else if *listInteropEndpoints {
		jsonOut, _ := json.Marshal(getEndpoints())
		fmt.Print(string(jsonOut))
	} else if *clientName != "" && *serverName != "" && (*buildEndpoints || *runAllTests || *testcaseName != "") {
		var client, server endpoint
		var found bool
		if client, found = endpoints[*clientName]; !found {
			fmt.Printf("%s not found.\n", *clientName)
			os.Exit(1)
		} else if !client.client {
			fmt.Printf("%s cannot be run as a client.\n", *clientName)
			os.Exit(1)
		}
		if server, found = endpoints[*serverName]; !found {
			fmt.Printf("%s not found.\n", *serverName)
		} else if !server.server {
			fmt.Printf("%s cannot be run as a client.\n", *serverName)
			os.Exit(1)
		}

		if *runAllTests {
			if *buildEndpoints {
				err := doBuildEndpoints(client, server, *verbose)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}

			for _, name := range getTestcaseNamesSorted() {
				err := doTestcase(testcases[name], name, client, server, *verbose, true)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

				destDir := filepath.Join(generatedDir, fmt.Sprintf("%s-out", name))
				err = os.RemoveAll(destDir)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				err = os.Rename(testOutputsDir, destDir)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}
		} else if *testcaseName != "" {
			if t, ok := testcases[*testcaseName]; ok {
				if *buildEndpoints {
					err := doBuildEndpoints(client, server, *verbose)
					if err != nil {
						log.Printf("ERROR: %s", err.Error())
						os.Exit(1)
					}
				}
				err := doTestcase(t, *testcaseName, client, server, *verbose, false)
				if err != nil {
					log.Printf("ERROR: %s", err.Error())
					os.Exit(1)
				}
			} else {
				fmt.Printf("Testcase %s not found.\n", *testcaseName)
				os.Exit(1)
			}
		}
	} else if *processResults {
		err := processTestResults(*resultsPath)
		if err != nil {
			log.Fatalf("ERROR: %s\n", err)
		}
	} else {
		fmt.Print(usage)
	}
}
