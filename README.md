# (Work in Progress) TLS Interop Test Runner

The TLS Interop Test Runner aims to test interoperability between multiple implementations of TLS by running various tests involving clients and servers drawn from differing implementations.

It has been fashioned after the [QUIC Interop Runner](https://github.com/marten-seemann/quic-interop-runner).

## Quickstart

1. `cd implementations/boringssl && docker build -t bssl-endpoint .`
2. `cd implementations/cloudflare-go && docker build -t cf-go-endpoint .`
3. `docker network create interop-net`
4. `docker run -t --rm --name bssl-server --network interop-net bssl-endpoint`
5. `docker run -t --rm --name go-cf-client --network interop-net cf-go-endpoint`
