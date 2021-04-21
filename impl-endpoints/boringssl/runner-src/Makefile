BORINGSSL_DIR = /boringssl
CXXFLAGS = -std=c++11 -I${BORINGSSL_DIR}/include
LDFLAGS = -L${BORINGSSL_DIR}/build/ssl -lssl -L${BORINGSSL_DIR}/build/crypto -lcrypto -lpthread
RUNNER_SRCS = args.cc client.cc server.cc fd.cc file.cc runner.cc transport_common.cc

runner: ${RUNNER_SRCS}
	$(CXX) $(CXXFLAGS) $^ -o $@ ${LDFLAGS}
