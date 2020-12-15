# (Work in Progress) TLS Interop Test Runner

The TLS Interop Test Runner aims to test interoperability between implementations of TLS by running various tests involving clients and servers drawn from differing implementations.

It is fashioned after the [QUIC Interop Runner](https://github.com/marten-seemann/quic-interop-runner).

## Quickstart

1. `make certs`
3. `env SERVER={rustls|boringssl} CLIENT=cloudflare-go docker-compose build`
4. `env SERVER={rustls|boringssl} CLIENT=cloudflare-go docker-compose up`
