FROM rust:1.79.0-buster AS builder

LABEL version="1.8.1"
LABEL name="Cosmian CLI and PKCS11 container"

ENV OPENSSL_DIR=/usr/local/openssl

WORKDIR /root

COPY . /root/cli

WORKDIR /root/cli

ARG TARGETPLATFORM
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then export ARCHITECTURE=x86_64; elif [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then export ARCHITECTURE=arm; elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then export ARCHITECTURE=arm64; else export ARCHITECTURE=x86_64; fi \
  && bash /root/cli/.github/reusable_scripts/get_openssl_binaries.sh

RUN cargo build -p cosmian_cli -p cosmian_pkcs11 --release

#
# KMS server
#
FROM debian:buster-slim AS cli

COPY --from=builder /root/cli/target/release/cosmian                  /usr/bin/
COPY --from=builder /root/cli/target/release/libcosmian_pkcs11.so     /usr/lib/
