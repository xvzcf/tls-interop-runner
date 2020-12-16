FROM golang:alpine AS builder

RUN apk add build-base \
            bash \
            git && \
    git clone --depth 1 --branch cf-delegated-credentials https://github.com/cloudflare/go /cf-go

WORKDIR /cf-go/src
RUN ./make.bash

FROM alpine:3.12

COPY --from=builder /cf-go /cf-go

COPY client.go /

COPY run_endpoint.sh /
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
