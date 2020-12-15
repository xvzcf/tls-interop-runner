FROM golang:alpine AS builder

RUN apk update && \
    apk upgrade && \
    apk add build-base \
            linux-headers \
            git \
            cmake \
            ninja \
            perl && \
    git clone --depth 1 --branch dc-update-09 https://github.com/xvzcf/boringssl /boringssl

RUN mkdir /boringssl/build
WORKDIR /boringssl/build
RUN cmake .. -G"Ninja" && ninja

FROM alpine:3.12

RUN apk add gcc

COPY --from=builder /boringssl/build/tool/bssl /usr/bin/
COPY --from=builder /boringssl/build/ssl/test/bssl_shim /usr/bin/

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
