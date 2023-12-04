# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM golang:latest AS builder

RUN apt-get update && \
    apt-get install -y git cmake ninja-build perl && \
    git clone --branch master https://boringssl.googlesource.com/boringssl /boringssl

WORKDIR /boringssl
RUN git checkout f78fe19fc98e0e6f760e05c6b9d48725004700d0

RUN mkdir /boringssl/build
WORKDIR /boringssl/build
RUN cmake .. -G"Ninja" && ninja

COPY runner-src /runner-src
WORKDIR /runner-src
RUN make

FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y net-tools tcpdump ethtool iproute2 python3

COPY --from=builder /runner-src/runner /runner

COPY ech-key-converter.py /

COPY run-endpoint.sh /

ENTRYPOINT [ "sh", "/run-endpoint.sh" ]
