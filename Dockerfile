FROM rust:1.79.0-buster AS builder

LABEL version="0.4.0"
LABEL name="Cosmian PKCS11 library container"

ENV OPENSSL_DIR=/usr/local/openssl

# Add build argument for FIPS mode
ARG FIPS=false

WORKDIR /root

RUN git clone https://github.com/Cosmian/reusable_scripts.git

COPY . /root/kms

WORKDIR /root/kms

ARG TARGETPLATFORM
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then export ARCHITECTURE=x86_64; elif [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then export ARCHITECTURE=arm; elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then export ARCHITECTURE=arm64; else export ARCHITECTURE=x86_64; fi \
  && bash /root/reusable_scripts/.github/scripts/get_openssl_binaries.sh

# Conditional cargo build based on FIPS argument
RUN if [ "$FIPS" = "true" ]; then \
  cargo build -p cosmian_pkcs11 --release --no-default-features --features="fips"; \
  else \
  cargo build -p cosmian_pkcs11 --release --no-default-features; \
  fi

#
# KMS server
#
FROM debian:buster-slim AS kms-server

COPY --from=builder /root/kms/target/release/libcosmian_pkcs11.so        /usr/bin/
