# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM golang:latest AS builder

RUN apt-get update && \
    apt-get install -y git cmake ninja-build perl && \
    git clone --branch master https://boringssl.googlesource.com/boringssl /boringssl

WORKDIR /boringssl
#RUN git checkout 1f51cfc7d7f54d2bee30bb5793470ef9c36a5083

RUN mkdir /boringssl/build
WORKDIR /boringssl/build
RUN cmake .. -G"Ninja" && ninja

COPY runner-src /runner-src
WORKDIR /runner-src
RUN make

FROM ubuntu:20.04
#RUN echo 'nameserver 8.8.8.8'>/etc/resolv.conf

RUN apt-get update && \
    apt-get install -y net-tools tcpdump ethtool iproute2 python3

COPY --from=builder /runner-src/runner /runner

COPY ech-key-converter.py /

COPY run-endpoint.sh /

ENTRYPOINT [ "sh", "/run-endpoint.sh" ]
