<!-- SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

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

Tests require certificates and other cryptographic artifacts to be generated
beforehand.

```
make testinputs
```

This command will generate:
* A root certificate
* Intermediate certificates
* A delegated credential
* ECH configuration files

Tests are run with `docker-compose`, with the artifacts copied into a virtual
volume. To run a test, you must first build the endpoints. For example, to build
a BoringSSL server and Cloudflare-Go client:

```
./build.sh cloudflare-go boringssl
```

You're now ready to run tests. The test case is also specified by setting an
environment variable. For example, to run the server-side delegated credential
test:

```
./run.sh cloudflare-go boringssl dc
```
