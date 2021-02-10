# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: CC0-1.0

TESTDATA_DIR = generated/test-inputs
DCVECTORS_DIR = dc_vectors
BIN_DIR = bin
UTIL = ${BIN_DIR}/util
UTIL_SRCS = $(wildcard cmd/util/*.go)

VALIDATEPCAP = ${BIN_DIR}/validatepcap
VALIDATEPCAP_SRCS = $(wildcard cmd/validatepcap/*.go)

all: testinputs

util: $(UTIL_SRCS)
	mkdir -p ${BIN_DIR}
	go get ./cmd/util/...
	go build -o ${UTIL} ./cmd/util/...

validatepcap: $(VALIDATEPCAP_SRCS)
	mkdir -p ${BIN_DIR}
	go get ./cmd/validatepcap/...
	go build -o ${VALIDATEPCAP} ./cmd/validatepcap/...

.PHONY: testinputs
testinputs: util
	mkdir -p ${TESTDATA_DIR}
	${UTIL} -make-root -out ${TESTDATA_DIR}/root.crt -key-out ${TESTDATA_DIR}/root.key -host root.com
	${UTIL} -make-intermediate -cert-in ${TESTDATA_DIR}/root.crt -key-in ${TESTDATA_DIR}/root.key -out ${TESTDATA_DIR}/example.crt -key-out ${TESTDATA_DIR}/example.key -host example.com
	${UTIL} -make-intermediate -cert-in ${TESTDATA_DIR}/root.crt -key-in ${TESTDATA_DIR}/root.key -out ${TESTDATA_DIR}/client-facing.crt -key-out ${TESTDATA_DIR}/client-facing.key -host client-facing.com
	${UTIL} -make-dc -cert-in ${TESTDATA_DIR}/example.crt -key-in ${TESTDATA_DIR}/example.key -out ${TESTDATA_DIR}/dc.txt
	${UTIL} -make-ech -out ${TESTDATA_DIR}/ech_configs -key-out ${TESTDATA_DIR}/ech_key -host client-facing.com
	${UTIL} -make-ech -out ${TESTDATA_DIR}/ech_configs_invalid -key-out /dev/null -host client-facing.com

dcvectors: util
	mkdir -p ${DCVECTORS_DIR}
	${UTIL} -make-root -out ${DCVECTORS_DIR}/root.crt -key-out ${DCVECTORS_DIR}/root.key -host root.com
	${UTIL} -make-intermediate -cert-in ${DCVECTORS_DIR}/root.crt -key-in ${DCVECTORS_DIR}/root.key -out ${DCVECTORS_DIR}/example.crt -key-out ${DCVECTORS_DIR}/example.key -host example.com
	${UTIL} -make-intermediate -cert-in ${DCVECTORS_DIR}/root.crt -key-in ${DCVECTORS_DIR}/root.key -out ${DCVECTORS_DIR}/client_facing.crt -key-out ${DCVECTORS_DIR}/client_facing.key -host client-facing.com
	${UTIL} -make-dcvectors -cert-in ${DCVECTORS_DIR}/example.crt -key-in ${DCVECTORS_DIR}/example.key -dc-algo 0x0807 -out ${DCVECTORS_DIR}/dc_ed25519.txt
	${UTIL} -make-dcvectors -cert-in ${DCVECTORS_DIR}/example.crt -key-in ${DCVECTORS_DIR}/example.key -dc-algo 0x0403 -out ${DCVECTORS_DIR}/dc_ecdsa_p256.txt
	${UTIL} -make-dcvectors -cert-in ${DCVECTORS_DIR}/example.crt -key-in ${DCVECTORS_DIR}/example.key -dc-algo 0x0503 -out ${DCVECTORS_DIR}/dc_ecdsa_p384.txt
	${UTIL} -make-dcvectors -cert-in ${DCVECTORS_DIR}/example.crt -key-in ${DCVECTORS_DIR}/example.key -dc-algo 0x0603 -out ${DCVECTORS_DIR}/dc_ecdsa_p512.txt

clean:
	rm -fr ${BIN_DIR}
	rm -fr ${TESTDATA_DIR}
	rm -fr ${DCVECTORS_DIR}

clean-docker:
	docker network prune
	docker builder prune
