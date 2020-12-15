FROM rust:1.44 AS builder

RUN git clone https://github.com/ctz/rustls.git /rustls

WORKDIR /rustls 

RUN git rev-parse HEAD > /commit.txt
RUN cargo build --examples --release

FROM ubuntu:latest
RUN apt-get update -y
RUN apt-get install python3 -y

COPY --from=builder /commit.txt /
COPY --from=builder /rustls/test-ca/ecdsa/end.fullchain /
COPY --from=builder /rustls/test-ca/ecdsa/end.key /
COPY --from=builder /rustls/target/release/examples/* /usr/bin/

COPY run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT [ "/run_endpoint.sh" ]
