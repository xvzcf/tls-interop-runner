FROM rust:1.44 AS builder

RUN git clone https://github.com/ctz/rustls.git /rustls

WORKDIR /rustls

RUN git rev-parse HEAD > /commit.txt
RUN cargo build --examples --release

FROM ubuntu:20.04
RUN apt-get update && \
    apt-get install -y python3 net-tools tcpdump ethtool iproute2

COPY --from=builder /commit.txt /
COPY --from=builder /rustls/target/release/examples/* /usr/bin/

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
