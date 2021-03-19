// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const usage = `Usage:

    $ runner [--help] {--client STRING} {--server STRING} {--testcase STRING|--alltestcases} [--build] [--verbose]

    $ runner --client=boringssl --server=cloudflare-go --build builds boringssl as a client and cloudflare-go as a server (and all their dependent services)
    $ runner --client=boringssl --server=cloudflare-go --testcase=dc [--build] (rebuilds the endpoints, their dependencies, then) runs just the dc test with boringssl as client and cloudflare-go as server
    $ runner --client=boringssl --server=cloudflare-go --alltestcases [--build] (rebuilds the endpoints, their dependencies, then) runs all testcases with boringssl as client and cloudflare-go as server
`

var testInputsDir = filepath.Join("generated", "test-inputs")
var testOutputsDir = filepath.Join("generated", "test-outputs")

var verboseMode = flag.Bool("verbose", false, "")

func main() {
	log.SetFlags(0)
	var (
		clientName           = flag.String("client", "", "")
		serverName           = flag.String("server", "", "")
		testCaseName         = flag.String("testcase", "", "")
		buildServices        = flag.Bool("build", false, "")
		runAllTests          = flag.Bool("alltestcases", false, "")
		listInteropClients   = flag.Bool("list-interop-clients", false, "")
		listInteropServers   = flag.Bool("list-interop-servers", false, "")
		listInteropEndpoints = flag.Bool("list-interop-endpoints", false, "")
		help                 = flag.Bool("help", false, "")
	)
	flag.Parse()
	if *help {
		fmt.Print(usage)
	} else if *listInteropClients {
		var clientNames []string
		for _, e := range endpoints {
			if e.client && !e.regression {
				clientNames = append(clientNames, e.name)
			}
		}
		jsonOut, _ := json.Marshal(clientNames)
		fmt.Print(string(jsonOut))
	} else if *listInteropServers {
		var serverNames []string
		for _, e := range endpoints {
			if e.client && !e.regression {
				serverNames = append(serverNames, e.name)
			}
		}
		jsonOut, _ := json.Marshal(serverNames)
		fmt.Print(string(jsonOut))
	} else if *listInteropEndpoints {
		var endpointNames []string
		for _, e := range endpoints {
			if e.client && !e.regression {
				endpointNames = append(endpointNames, e.name)
			}
		}
		jsonOut, _ := json.Marshal(endpointNames)
		fmt.Print(string(jsonOut))
	} else if *clientName != "" && *serverName != "" && (*buildServices || *runAllTests || *testCaseName != "") {
		var client, server endpoint
		var found bool
		if client, found = endpoints[*clientName]; !found {
			log.Fatalf("%s not found.", *clientName)
		} else if !client.client {
			log.Fatalf("%s cannot be run as a client.", *clientName)
		}
		if server, found = endpoints[*serverName]; !found {
			log.Fatalf("%s not found.", *serverName)
		} else if !server.server {
			log.Fatalf("%s cannot be run as a client.", *serverName)
		}

		if *buildServices {
			log.Printf("Building %s client and %s server.\n", client.name, server.name)
			cmd := exec.Command("docker-compose", "build")
			env := os.Environ()
			if client.regression {
				env = append(env, "CLIENT_SRC=regression-endpoints")
			} else {
				env = append(env, "CLIENT_SRC=impl-endpoints")
			}
			env = append(env, fmt.Sprintf("CLIENT=%s", client.name))
			if server.regression {
				env = append(env, "SERVER_SRC=regression-endpoints")
			} else {
				env = append(env, "SERVER_SRC=impl-endpoints")
			}
			env = append(env, fmt.Sprintf("SERVER=%s", server.name))
			cmd.Env = env
			err := cmd.Run()
			if err != nil {
				log.Fatalf("docker-compose build: %s", err)
			}
			log.Println("Done.")
		}

		if *runAllTests {
			for name, t := range testCases {
				err := t.setup()
				if err != nil {
					log.Fatal("Error generating test inputs.")
				}
				fmt.Printf("client=%s,server=%s,", client.name, server.name)
				err = t.run(client, server)
				if err != nil {
					log.Println(err)
					goto moveOutputs
				}
				err = t.verify()
				if err != nil {
					log.Println(err)
					goto moveOutputs
				}
				log.Println("Success")
			moveOutputs:
				destDir := filepath.Join("generated", fmt.Sprintf("%s-out", name))
				err = os.RemoveAll(destDir)
				if err != nil {
					log.Fatal(err)
				}
				err = os.Rename(testOutputsDir, destDir)
				if err != nil {
					log.Fatal(err)
				}
			}
		} else if *testCaseName != "" {
			if t, ok := testCases[*testCaseName]; ok {
				err := t.setup()
				if err != nil {
					log.Fatal("Error generating test inputs.")
				}
				err = t.run(client, server)
				if err != nil {
					log.Fatal(err.Error())
				}
				err = t.verify()
				if err != nil {
					log.Fatal(err.Error())
				}
				log.Println("Success")
			} else {
				log.Fatalf("Testcase %s not found.\n", *testCaseName)
			}
		}
	} else {
		fmt.Print(usage)
	}
}
