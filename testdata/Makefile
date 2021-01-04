CERT_TOOL_FILES = $(wildcard cert-tool-src/*.go)

all: certs dc

cert-tool: $(CERT_TOOL_FILES)
	go build -o cert-tool $^

.PHONY: certs
certs: cert-tool
	rm -f root.key root.cert server.key server.cert
	./cert-tool -make-root -out root.cert -key-out root.key
	./cert-tool -make-intermediate -cert-in root.cert -key-in root.key -out server.cert -key-out server.key

.PHONY: dc
dc: server.cert server.key cert-tool
	rm -f rm -f dc.txt
	./cert-tool -make-dc -cert-in server.cert -key-in server.key -out dc.txt

clean:
	rm cert-tool
