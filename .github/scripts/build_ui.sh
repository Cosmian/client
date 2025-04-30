#!/bin/bash

# Build the KMS WASM dep for UI

# Exit on error, print commands
set -ex

if [ -n "$FEATURES" ]; then
  FEATURES="--features $FEATURES"
fi

# Install wasm-pack tool
cargo install --version 0.13.1 wasm-pack --force

# Build WASM component
cd crate/wasm
# shellcheck disable=SC2086
RUSTUP_TOOLCHAIN="nightly-2025-01-01" wasm-pack build --target web --release $FEATURES
