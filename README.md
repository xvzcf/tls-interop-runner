# (Work in Progress) TLS Interop Test Runner

The TLS Interop Test Runner aims to test interoperability between
implementations of TLS by running various tests involving clients and servers
drawn from differing implementations.

It is fashioned after the [QUIC Interop
Runner](https://github.com/marten-seemann/quic-interop-runner).

## Quickstart

You will need to have golang installed.

You will need to clone this repository on the `src` directory of your
`$GOPATH`. To learn your `$GOPATH`, use `go env`.

Tests are run with `docker-compose`. To run a test, you must first build the
endpoints. For example, to build a boringSSL server and Cloudflare-Go client:

```
env SERVER_SRC=./impl-endpoints SERVER=boringssl \
    CLIENT_SRC=./impl-endpoints CLIENT=cloudflare-go \
    docker-compose build
```

Tests require certificates and other cryptographic artifacts to be generated
beforehand.

```
make testdata
```

This command will generate:
* A root certificate
* Intermediate certificates
* A delegated credential
* ECH configuration files

You're now ready to run tests. The test case is also specified by setting an
environment variable. For example, to run the server-side delegated credential
test:

```
env SERVER_SRC=./impl-endpoints SERVER=boringssl \
    CLIENT_SRC=./impl-endpoints CLIENT=cloudflare-go \
    TESTCASE=dc docker-compose up
```
