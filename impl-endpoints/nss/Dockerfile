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
 && rm -rf /var/lib/apt/lists/* \
 && apt-get autoremove -y && apt-get clean -y

RUN mkdir /build
WORKDIR /build

# Clone and build. Output in /nss/dist/Debug/.
RUN cd /build \
   && hg clone https://hg.mozilla.org/projects/nspr \
        --rev b09175587dad2bfb923ec87250ac80461f620577 \
   && hg clone https://hg.mozilla.org/projects/nss \
   && cd nss \
   && hg pull -u -r 98542d9c204f8e91336f0a36239d776d82dc8989 https://hg.mozilla.org/projects/nss-try \
   && ./build.sh -Denable_draft_hpke=1 \
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

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
