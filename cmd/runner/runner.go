// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"errors"
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

func main() {
	var (
		clientName           = flag.String("client", "", "")
		serverName           = flag.String("server", "", "")
		testCaseName         = flag.String("testcase", "", "")
		doBuildEndpoints     = flag.Bool("build", false, "")
		runAllTests          = flag.Bool("alltestcases", false, "")
		listInteropClients   = flag.Bool("list-interop-clients", false, "")
		listInteropServers   = flag.Bool("list-interop-servers", false, "")
		listInteropEndpoints = flag.Bool("list-interop-endpoints", false, "")
		verbose              = flag.Bool("verbose", false, "")
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
	} else if *clientName != "" && *serverName != "" && (*doBuildEndpoints || *runAllTests || *testCaseName != "") {
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
			if *doBuildEndpoints {
				fmt.Printf("Building %s client and %s server.\n", client.name, server.name)
				err := buildEndpoints(client, server, *verbose)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				fmt.Printf("Done.\n")
			}

			for name, t := range testCases {
				runLog, err := t.setup(*verbose)
				if err != nil {
					runLog.Close()
					fmt.Println("Error generating test inputs.")
					os.Exit(1)
				}

				fmt.Printf("testcase=%s,client=%s,server=%s,", name, client.name, server.name)
				err = t.run(client, server)
				if err != nil {
					fmt.Println(err)
					goto moveTestOutputs
				}

				err = t.verify()
				if err != nil {
					fmt.Println(err)
					goto moveTestOutputs
				}
				fmt.Println("Success")

			moveTestOutputs:
				runLog.Close()
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
				if *doBuildEndpoints {
					fmt.Printf("Building %s client and %s server.\n", client.name, server.name)
					err := buildEndpoints(client, server, *verbose)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}
					fmt.Printf("Done.\n")
				}

				runLog, err := t.setup(*verbose)
				if err != nil {
					err = errors.New("Error generating test inputs.")
					goto testError
				}

				err = t.run(client, server)
				if err != nil {
					goto testError
				}

				err = t.verify()
				if err != nil {
					goto testError
				}
				goto testSuccess
			testError:
				runLog.Close()
				fmt.Println(err)
				os.Exit(1)
			testSuccess:
				runLog.Close()
				fmt.Println("Success")
			} else {
				fmt.Printf("Testcase %s not found.\n", *testCaseName)
				os.Exit(1)
			}
		}
	} else {
		fmt.Print(usage)
	}
}

func buildEndpoints(client endpoint, server endpoint, verbose bool) error {
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
	// TESTCASE is not needed at this point, and is just
	// set to suppress unset variable warnings.
	env = append(env, "TESTCASE=\"\"")
	cmd.Env = env
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("docker-compose build: %s", err)
	}
	return nil
}
