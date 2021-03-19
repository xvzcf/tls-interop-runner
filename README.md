<!-- SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors -->
<!-- SPDX-License-Identifier: CC0-1.0 -->

# (Work in Progress) TLS Interop Test Runner

The TLS Interop Test Runner aims to test interoperability between
implementations of TLS by running various tests involving clients and servers
drawn from differing implementations.

It is fashioned after the [QUIC Interop
Runner](https://github.com/marten-seemann/quic-interop-runner).

## Requirements

- Tshark >= 3.2.0 present in the PATH
- Go >= 1.15
- A sufficiently recent version of `docker` and `docker-compose`

## Quickstart

0. Clone this repository to the `src` directory of your `$GOPATH`.
To learn your `$GOPATH`, use `go env`.

1. Build the interop runner. The runner can then be invoked as `./bin/runner`
```
make runner
```

2. Tests are run with `docker-compose`, with the artifacts copied into a virtual
volume. To run a test with, say, BoringSSL as server and Cloudflare-Go as client,
you must first build the necessary docker images:
```
./bin/runner --client=boringssl --server=cloudflare-go --build
```

3. You're now ready to run tests. For example, to run the server-side delegated credential
test:

```
./bin/runner --client=cloudflare-go --server=boringssl --testcase=dc
```
