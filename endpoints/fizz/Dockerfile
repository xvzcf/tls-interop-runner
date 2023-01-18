# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM ubuntu:latest AS builder

RUN apt-get update && \
    DEBIAN_FRONTEND= apt-get install -y git g++ cmake make pkg-config python3 m4 libssl-dev libz-dev

RUN git clone https://github.com/NickR23/fizz.git /fizz
WORKDIR /fizz

WORKDIR /fizz/build
RUN mkdir /output
RUN python3 fbcode_builder/getdeps.py --install-prefix=/output build fizz --src-dir=.. --extra-cmake-defines '{"BUILD_EXAMPLES": true, "BUILD_SHARED_LIBS": false, "USE_STATIC_DEPS_ON_UNIX": true}'

FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y net-tools tcpdump ethtool iproute2 python3 bash

COPY --from=builder /fizz /fizz
COPY --from=builder /output /output
# COPY --from=builder /runner-src/runner /usr/bin/

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
COPY ech_key_converter.py /ech_key_converter.py
RUN chmod +x /ech_key_converter.py

ENTRYPOINT [ "/run_endpoint.sh" ]
