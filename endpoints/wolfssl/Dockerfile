# SPDX-FileCopyrightText: 2023 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM ubuntu:24.04 AS builder

RUN apt-get update
RUN apt-get install -y build-essential git autotools-dev autoconf libtool
RUN git clone --branch master https://github.com/wolfSSL/wolfssl.git wolfssl-src

WORKDIR /wolfssl-src
RUN git checkout 195c14ccafeec1669d80b02a877e078bb5d238de
RUN ./autogen.sh
RUN ./configure --enable-ech --prefix=/wolfssl
RUN make && make install

COPY runner-srcs /runner-srcs
WORKDIR /runner-srcs
RUN make

FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y net-tools tcpdump ethtool iproute2 python3

COPY --from=builder /runner-srcs/client-ech /client-ech
COPY --from=builder /wolfssl /wolfssl

COPY ech-key-converter.py /

COPY run-endpoint.sh /

ENTRYPOINT [ "sh", "/run-endpoint.sh" ]
