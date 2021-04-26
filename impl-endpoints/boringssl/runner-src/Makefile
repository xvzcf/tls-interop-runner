# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

BORINGSSL_DIR = /boringssl
CXXFLAGS = -std=c++11 -Werror -Wformat=2 -Wsign-compare -Wmissing-field-initializers -Wwrite-strings -Wvla -Wno-implicit-fallthrough -I${BORINGSSL_DIR}/include
LDFLAGS = -L${BORINGSSL_DIR}/build/ssl -lssl -L${BORINGSSL_DIR}/build/crypto -lcrypto -lpthread
RUNNER_SRCS = args.cc client.cc server.cc file.cc runner.cc transport_common.cc

runner: ${RUNNER_SRCS}
	$(CXX) $(CXXFLAGS) $^ -o $@ ${LDFLAGS}
