# (Work in Progress) TLS Interop Test Runner

The TLS Interop Test Runner aims to test interoperability between
implementations of TLS by running various tests involving clients and servers
drawn from differing implementations.

It is fashioned after the [QUIC Interop
Runner](https://github.com/marten-seemann/quic-interop-runner).

## Quickstart

Tests are run with `docker-compose`. To run a test, you must first build the
endpoints. For example, to build a boringSSL server and Cloudflare-Go client:

```
env SERVER_SRC=./impl-endpoints SERVER=boringssl \
    CLIENT_SRC=./impl-endpoints CLIENT=cloudflare-go \
    docker-compose build
```

Tests require certificates and other cryptographic artifacts to be generated
beforehand. To do so, you will need to have Go installed and make sure this
repository is in your $GOPATH (e.g.,
~/go/src/github.com/xvzcf/tls-interop-runner).

```
make certs
make dc
```

You're now ready to run tests. The test case is also specified by setting an
environment variable. For example, to run the server-side delegated credential
test:

```
env SERVER_SRC=./impl-endpoints SERVER=boringssl \
    CLIENT_SRC=./impl-endpoints CLIENT=cloudflare-go \
    TESTCASE=dc docker-compose up
```
