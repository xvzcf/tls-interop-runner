# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM golang:latest AS builder

RUN apt-get update && \
    apt-get install git
RUN git clone --branch caw/ech-10 https://github.com/cloudflare/go /cf

WORKDIR /cf/src
# RUN git checkout 2a17ea31d28264fccfec4e59dc2ac733b6c73dec
RUN ./make.bash

FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y net-tools tcpdump ethtool iproute2

COPY --from=builder /cf /cf

COPY runner.go config.go /

RUN /cf/bin/go build -o /usr/bin/runner runner.go config.go

COPY run_endpoint.sh /
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
