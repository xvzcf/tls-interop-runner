// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

type endpoint struct {
	name       string
	regression bool
	client     bool
	server     bool
}

var endpoints = map[string]endpoint{
	"boringssl": {
		name:       "boringssl",
		regression: false,
		client:     true,
		server:     true,
	},
	"cloudflare-go": {
		name:       "cloudflare-go",
		regression: false,
		client:     true,
		server:     true,
	},
}
