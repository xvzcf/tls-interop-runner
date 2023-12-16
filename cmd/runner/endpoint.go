// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
)

type endpoint struct {
	name   string
	client bool
	server bool
	url    string
}

var endpoints = map[string]endpoint{
	"boringssl": {
		name:   "boringssl",
		client: true,
		server: true,
		url:    "https://boringssl.googlesource.com/boringssl",
	},
	"cloudflare-go": {
		name:   "cloudflare-go",
		client: true,
		server: true,
		url:    "https://github.com/cloudflare/go",
	},
	"nss": {
		name:   "nss",
		client: true,
		server: true,
		url:    "https://hg.mozilla.org/projects/nss",
	},
	"wolfssl": {
		name:   "wolfssl",
		client: true,
		server: false,
		url:    "https://www.wolfssl.com/",
	},
}

func getClients() []string {
	var clientNames []string
	for _, e := range endpoints {
		if e.client {
			clientNames = append(clientNames, e.name)
		}
	}
	sort.Strings(clientNames)
	return clientNames
}

func getServers() []string {
	var serverNames []string
	for _, e := range endpoints {
		if e.server {
			serverNames = append(serverNames, e.name)
		}
	}
	sort.Strings(serverNames)
	return serverNames
}

func getEndpoints() []string {
	var endpointNames []string
	for _, e := range endpoints {
		endpointNames = append(endpointNames, e.name)
	}
	sort.Strings(endpointNames)
	return endpointNames
}

func doBuildEndpoints(client endpoint, server endpoint, verbose bool) error {
	log.Printf("Building %s client and %s server.\n", client.name, server.name)

	cmd := exec.Command("docker", "compose", "build")
	env := os.Environ()

	env = append(env, "DOCKER_SCAN_SUGGEST=false")

	env = append(env, fmt.Sprintf("CLIENT=%s", client.name))
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
