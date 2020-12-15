# TODO: Find an alternative for Windows

CERT_TOOL_FILES = $(wildcard cert-tool-src/*.go)

cert-tool: $(CERT_TOOL_FILES)
	go build -o cert-tool $^

certs: cert-tool
	rm -rf certs && mkdir certs
	cert-tool -CA
	cert-tool -cert-out certs/server.cert -key-out certs/server.key server
