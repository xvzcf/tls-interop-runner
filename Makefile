CERT_TOOL_FILES = $(wildcard cert-tool-src/*.go)

cert-tool: $(CERT_TOOL_FILES)
	go build -o cert-tool $^

.PHONY: certs
certs: cert-tool
	rm -rf certs && mkdir certs
	./cert-tool -make-root -out certs/rootCA.pem -key-out certs/rootCA.key
	./cert-tool -make-intermediate -cert-in certs/rootCA.pem -key-in certs/rootCA.key -out certs/server.cert -key-out certs/server.key

dc: certs/server.cert certs/server.key cert-tool
	./cert-tool -make-dc -cert-in certs/server.cert -key-in certs/server.key -out certs/dc.txt

clean:
	docker builder prune
