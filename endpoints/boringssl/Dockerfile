# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM golang:latest AS builder

RUN apt-get update && \
    apt-get install -y git cmake ninja-build perl && \
    git clone --branch master https://boringssl.googlesource.com/boringssl /boringssl

WORKDIR /boringssl
RUN git checkout 295b31324f8c557dcd3c1c831857e33a7f23bc52

RUN mkdir /boringssl/build
WORKDIR /boringssl/build
RUN cmake .. -G"Ninja" && ninja

COPY runner-src /runner-src
WORKDIR /runner-src
RUN make

FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y net-tools tcpdump ethtool iproute2 python3

COPY --from=builder /boringssl/build/tool/bssl /usr/bin/
COPY --from=builder /runner-src/runner /usr/bin/

COPY ech_key_converter.py /

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
