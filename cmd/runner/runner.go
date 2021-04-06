// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
		testcaseName         = flag.String("testcase", "", "")
		buildEndpoints       = flag.Bool("build", false, "")
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
			for name, t := range testcases {
				err := doTestcase(t, name, client, server, *verbose, true)
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
	} else {
		fmt.Print(usage)
	}
}

func doBuildEndpoints(client endpoint, server endpoint, verbose bool) error {
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

	log.Printf("Building done.\n")
	return nil
}

func doTestcase(t testcase, testcaseName string, client endpoint, server endpoint, verbose bool, allTestsMode bool) error {
	log.Println("\nTesting: " + testcaseName)
	var result resultType

	err := t.setup(verbose)
	if err != nil {
		goto teardown
	}

	result, err = t.run(client, server)
	if result != resultSuccess {
		goto teardown
	}

	result, err = t.verify()
	if result != resultSuccess {
		goto teardown
	}
teardown:
	testcaseError := err

	testStatusFile, err := os.Create(filepath.Join(testOutputsDir, "test.txt"))
	if err != nil {
		return fmt.Errorf("error creating test status file: %s", err)
	}
	testStatusLogger := log.New(io.MultiWriter(os.Stdout, testStatusFile), "", 0)

	if testcaseError != nil {
		testStatusLogger.Printf("%s,%s,%s,%v,%s", client.name, server.name, testcaseName, result, testcaseError)
	} else {
		testStatusLogger.Printf("%s,%s,%s,%v", client.name, server.name, testcaseName, result)
	}
	testStatusFile.Close()

	err = t.teardown(allTestsMode)
	if err != nil {
		return fmt.Errorf("Error tearing down: %s", err)
	}

	if !allTestsMode {
		return testcaseError
	}
	return nil
}
