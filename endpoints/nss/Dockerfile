# SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
# SPDX-License-Identifier: MIT

FROM golang:latest AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    gyp \
    mercurial \
    ninja-build \
    zlib1g-dev \
    python \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get autoremove -y && apt-get clean -y

RUN mkdir /build
WORKDIR /build

# Clone and build. Output in /nss/dist/Debug/.
RUN cd /build \
   && hg clone https://hg.mozilla.org/projects/nspr \
        --rev 08516dbcdb20f6bdb1f918857e5a5b973d1e9feb \
   && hg clone https://hg.mozilla.org/projects/nss \
        --rev 841fad6dbcfd150eeeb2c83f2dc69d7acb180cdb \
   && cd nss \
   && ./build.sh \
   && cd /

FROM ubuntu:20.04
COPY --from=builder /build/dist/Debug/bin/* /usr/bin/
COPY --from=builder /build/dist/Debug/lib/* /usr/lib/

# Setup the nss database
RUN mkdir /db && cd /db \
   && certutil -N -d . --empty-password

RUN apt-get update && \
    apt-get install -y \
    net-tools \
    tcpdump \
    ethtool \
    iproute2 \
    python3 \
    openssl

COPY ech_key_converter.py /

COPY run-endpoint.sh /

ENTRYPOINT [ "sh", "/run-endpoint.sh" ]
