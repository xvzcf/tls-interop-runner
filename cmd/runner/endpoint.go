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
	"tls-attacker": {
		name:       "tls-attacker",
		regression: true,
		client:     true,
		server:     false,
	},
}
