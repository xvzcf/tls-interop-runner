# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: CC0-1.0

TESTDATA_DIR = generated/test-inputs
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

# TODO(claucece): replace this makefile creation with golden files created by golang itself
algorithms := 0x0807 0x0403 0x0503 0x0603
r = $(shell awk -v min=1 -v max=3 'BEGIN{srand(); print int(min+rand()*(max-min+1))}')
alg = $(word $(call r), $(algorithms))

.PHONY: testinputs
testinputs: util
	mkdir -p ${TESTDATA_DIR}
	${UTIL} -make-root -out ${TESTDATA_DIR}/root.crt -key-out ${TESTDATA_DIR}/root.key -host root.com
	${UTIL} -make-intermediate -cert-in ${TESTDATA_DIR}/root.crt -key-in ${TESTDATA_DIR}/root.key -out ${TESTDATA_DIR}/example.crt -key-out ${TESTDATA_DIR}/example.key -host example.com
	${UTIL} -make-intermediate -cert-in ${TESTDATA_DIR}/root.crt -key-in ${TESTDATA_DIR}/root.key -out ${TESTDATA_DIR}/client-facing.crt -key-out ${TESTDATA_DIR}/client-facing.key -host client-facing.com
	${UTIL} -make-dc -cert-in ${TESTDATA_DIR}/example.crt -key-in ${TESTDATA_DIR}/example.key -alg $(call alg) -out ${TESTDATA_DIR}/dc.txt
	${UTIL} -make-ech -out ${TESTDATA_DIR}/ech_configs -key-out ${TESTDATA_DIR}/ech_key -host client-facing.com
	${UTIL} -make-ech -out ${TESTDATA_DIR}/ech_configs_invalid -key-out /dev/null -host client-facing.com

clean:
	rm -fr ${BIN_DIR}
	rm -fr ${TESTDATA_DIR}

clean-docker:
	docker network prune
	docker builder prune
