# (Work in Progress) TLS Interop Test Runner

The TLS Interop Test Runner aims to test interoperability between implementations of TLS by running various tests involving clients and servers drawn from differing implementations.

It is fashioned after the [QUIC Interop Runner](https://github.com/marten-seemann/quic-interop-runner).

## Quickstart

0. `cd cert-utils && go build . && cd ..`
1. `mkdir certs && cert-utils/cert-utils -CA`
2. `./cert-utils/cert-utils -cert-out certs/server.cert -key-out certs/server.key server`
3. `env SERVER=boringssl CLIENT={cloudflare-go|rustls} docker-compose build`
4. `env SERVER=boringssl CLIENT={cloudflare-go|rustls} docker-compose up`
