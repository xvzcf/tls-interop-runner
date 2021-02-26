package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
)

const usage = `Usage:

    $ runner [-help] {[-client STRING] [-server STRING] [-testcase STRING]}

    $ runner -client=boringssl -server=cloudflare-go -testcase=dc runs just the dc test with the boringssl client and cloudflare-go server
    $ runner -client=boringssl -server=cloudflare-go -alltestcases runs all test cases with the boringssl client and cloudflare-go server
`

var testInputsDir = path.Join("generated", "test-inputs")
var testOutputsDir = path.Join("generated", "test-outputs")

func main() {
	log.SetFlags(0)
	var (
		clientName       = flag.String("client", "", "")
		serverName       = flag.String("server", "", "")
		testCaseName     = flag.String("testcase", "", "")
		runAllTests      = flag.Bool("alltestcases", false, "")
		listClientsForCI = flag.Bool("ci-list-clients", false, "")
		listServersForCI = flag.Bool("ci-list-servers", false, "")
		help             = flag.Bool("help", false, "")
	)
	flag.Parse()
	if *help {
		fmt.Print(usage)
	} else if *listClientsForCI {
		fmt.Printf("[")
		for i, e := range endpoints {
			if i > 0 {
				fmt.Printf(",")
			}
			if e.client {
				fmt.Printf("\"%s\"", e.name)
			}
		}
		fmt.Printf("]\n")
	} else if *listServersForCI {
		fmt.Printf("[")
		for i, e := range endpoints {
			if e.server {
				if i > 0 {
					fmt.Printf(",")
				}
				fmt.Printf("\"%s\"", e.name)
			}
		}
		fmt.Printf("]\n")
	} else if *clientName != "" && *serverName != "" && (*runAllTests || *testCaseName != "") {
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
		log.Printf("Building %s and %s.\n", client.name, server.name)
		cmd := exec.Command("docker-compose", "build")
		env := os.Environ()
		if server.regression {
			env = append(env, "SERVER_SRC=regression-endpoints")
		} else {
			env = append(env, "SERVER_SRC=impl-endpoints")
		}
		env = append(env, fmt.Sprintf("SERVER=%s", server.name))
		if client.regression {
			env = append(env, "CLIENT_SRC=regression-endpoints")
		} else {
			env = append(env, "CLIENT_SRC=impl-endpoints")
		}
		env = append(env, fmt.Sprintf("CLIENT=%s", client.name))
		cmd.Env = env
		err := cmd.Run()
		if err != nil {
			log.Fatalf("docker-compose build: %s", err)
		}
		if *runAllTests {
			for _, t := range testCases {
				err = t.setup()
				if err != nil {
					log.Fatal("Error generating test inputs.")
				}
				err = t.run(client, server, false)
				if err != nil {
					log.Fatal(err.Error())
				}
				err = t.verify()
				if err != nil {
					log.Fatal(err.Error())
				}
				log.Printf("Success\n")
			}
		} else if t, ok := testCases[*testCaseName]; ok {
			err = t.setup()
			if err != nil {
				log.Fatal("Error generating test inputs.")
			}
			err = t.run(client, server, true)
			if err != nil {
				log.Fatal(err.Error())
			}
			err = t.verify()
			if err != nil {
				log.Fatal(err.Error())
			}
			log.Printf("Success\n")
		} else {
			log.Fatalf("Testcase %s not found.\n", *testCaseName)
		}
	} else {
		fmt.Print(usage)
	}
}
