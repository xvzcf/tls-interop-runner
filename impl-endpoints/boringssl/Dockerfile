# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM golang:latest AS builder

RUN apt-get update && \
    apt-get install -y git cmake ninja-build perl && \
    git clone --branch dc-spec-update https://github.com/xvzcf/boringssl /boringssl

WORKDIR /boringssl
RUN git checkout 66929b751f97b3ce2868523bcdde549ea8324b56

RUN mkdir /boringssl/build
WORKDIR /boringssl/build
RUN cmake .. -G"Ninja" && ninja

FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y net-tools tcpdump ethtool iproute2

COPY --from=builder /boringssl/build/tool/bssl /usr/bin/

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
