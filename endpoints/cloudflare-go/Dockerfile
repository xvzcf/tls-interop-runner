# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM golang:latest AS builder

RUN apt-get update && \
    apt-get install git
RUN git clone https://github.com/cloudflare/go /cf

WORKDIR /cf/src
RUN git checkout 891ed94eba148802d1bc93c29fb137f83c6cfba1
RUN ./make.bash

FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y net-tools tcpdump ethtool iproute2

COPY --from=builder /cf /cf

COPY runner.go config.go /

RUN /cf/bin/go build -o /usr/bin/runner runner.go config.go

COPY run-endpoint.sh /

ENTRYPOINT [ "sh", "/run-endpoint.sh" ]
