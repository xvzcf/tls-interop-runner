# TODO: Find an alternative for Windows

CERT_TOOL_FILES = $(wildcard cert-tool-src/*.go)

cert-tool: $(CERT_TOOL_FILES)
	go build -o cert-tool $^

.PHONY: certs
certs: cert-tool
	rm -rf certs && mkdir certs
	./cert-tool -CA
	./cert-tool -cert-out certs/server.cert -key-out certs/server.key -dc-capable server

dc: certs/server.cert certs/server.key cert-tool
	./cert-tool -cert-in certs/server.cert -key-in certs/server.key -generate-dc -dc-out certs/dc.txt

clean:
	docker system prune -a
