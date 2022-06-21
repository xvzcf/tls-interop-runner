// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

type endpoint struct {
	name   string
	client bool
	server bool
}

var endpoints = map[string]endpoint{
	"boringssl": {
		name:   "boringssl",
		client: true,
		server: true,
	},
	"cloudflare-go": {
		name:   "cloudflare-go",
		client: true,
		server: true,
	},
	"nss": {
		name:   "nss",
		client: true,
		server: true,
	},
}
