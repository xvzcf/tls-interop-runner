package main

type endpoint struct {
	name       string
	regression bool
	client     bool
	server     bool
}

var endpoints = []endpoint{
	{
		name:       "boringssl",
		regression: false,
		client:     true,
		server:     true,
	},
	{
		name:       "cloudflare-go",
		regression: false,
		client:     true,
		server:     true,
	},
	{
		name:       "tlsfuzzer",
		regression: true,
		client:     true,
		server:     false,
	},
}
