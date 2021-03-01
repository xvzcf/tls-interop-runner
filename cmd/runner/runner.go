package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"
)

const usage = `Usage:

    $ runner [--help] {--client STRING} {--server STRING} {--testcase STRING|--alltestcases} [--build] [--build-network]

    $ runner --build-network builds the network simulator image.
    $ runner --client=boringssl --server=cloudflare-go --build builds boringssl as a client and cloudflare-go as a server
    $ runner --client=boringssl --server=cloudflare-go --testcase=dc runs just the dc test with the boringssl client and cloudflare-go server
    $ runner --client=boringssl --server=cloudflare-go --alltestcases runs all test cases with the boringssl client and cloudflare-go server
`

func main() {
	log.SetFlags(0)
	var (
		clientName           = flag.String("client", "", "")
		serverName           = flag.String("server", "", "")
		testCaseName         = flag.String("testcase", "", "")
		buildEndpoints       = flag.Bool("build", false, "")
		buildNetwork         = flag.Bool("build-network", false, "")
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
		fmt.Printf("[")
		for i, e := range endpoints {
			if e.client && !e.regression {
				if i > 0 {
					fmt.Printf(",")
				}
				fmt.Printf("\"%s\"", e.name)
			}
		}
		fmt.Printf("]\n")
	} else if *listInteropServers {
		fmt.Printf("[")
		for i, e := range endpoints {
			if e.server && !e.regression {
				if i > 0 {
					fmt.Printf(",")
				}
				fmt.Printf("\"%s\"", e.name)
			}
		}
		fmt.Printf("]\n")
	} else if *listInteropEndpoints {
		fmt.Printf("[")
		for i, e := range endpoints {
			if !e.regression {
				if i > 0 {
					fmt.Printf(",")
				}
				fmt.Printf("\"%s\"", e.name)
			}
		}
		fmt.Printf("]\n")
	} else if *buildNetwork {
		cmd := exec.Command("docker", "build", "network", "--tag", "tls-interop-network")
		err := cmd.Run()
		if err != nil {
			log.Fatalf("docker network build: %s", err)
		}
	} else if *clientName != "" && *serverName != "" && *buildEndpoints {
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

		log.Printf("Building %s.\n", client.name)
		var location string
		if client.regression {
			location = "regression-endpoints"
		} else {
			location = "impl-endpoints"
		}
		cmd := exec.Command("docker", "build",
			fmt.Sprintf("%s/%s", location, client.name),
			"--tag", fmt.Sprintf("tls-endpoint-%s", client.name))
		err := cmd.Run()
		if err != nil {
			log.Fatalf("docker build: %s", err)
		}

		log.Printf("Building %s.\n", server.name)
		if server.regression {
			location = "regression-endpoints"
		} else {
			location = "impl-endpoints"
		}
		cmd = exec.Command("docker", "build",
			fmt.Sprintf("%s/%s", location, server.name),
			"--tag", fmt.Sprintf("tls-endpoint-%s", server.name))
		err = cmd.Run()
		if err != nil {
			log.Fatalf("docker build: %s", err)
		}
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
		if *runAllTests {
			for _, t := range testCases {
				err := t.setup()
				if err != nil {
					log.Fatal("Error generating test inputs.")
				}
				fmt.Printf("client=%s,server=%s,", client.name, server.name)
				err = t.run(client, server, false)
				if err != nil {
					log.Println(err)
					continue
				}
				err = t.verify()
				if err != nil {
					log.Println(err)
					continue
				}
				log.Println("Success")
			}
		} else if t, ok := testCases[*testCaseName]; ok {
			err := t.setup()
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
			log.Println("Success")
		} else {
			log.Fatalf("Testcase %s not found.\n", *testCaseName)
		}
	} else {
		fmt.Print(usage)
	}
}
