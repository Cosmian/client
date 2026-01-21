#!/bin/bash

set -exo pipefail

# export FEATURES="non-fips"

if [ -z "$TARGET" ]; then
  echo "Error: TARGET is not set. Examples of TARGET are x86_64-unknown-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin."
  exit 1
fi

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  RELEASE="--release"
fi

if [ -n "$FEATURES" ]; then
  FEATURES="--features $FEATURES"
fi

if [ -z "$FEATURES" ]; then
  echo "Info: FEATURES is not set."
  unset FEATURES
fi

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set. Example OPENSSL_DIR=/usr/local/openssl"
  exit 1
fi

export RUST_LOG="cosmian_cli=error,cosmian_findex_client=debug,cosmian_kms_client=debug"

# shellcheck disable=SC2086
cargo test --workspace --bins --target $TARGET $RELEASE $FEATURES

# shellcheck disable=SC2086
# cargo bench --target $TARGET $FEATURES --no-run

export RUST_LOG="fatal,cosmian_cli=error,cosmian_findex_client=debug,cosmian_kms_client=debug"

# shellcheck disable=SC2086
cargo test --target $TARGET $RELEASE \
  --features non-fips \
  -p cosmian_cli \
  -p cosmian_pkcs11 \
  -- --nocapture

if [ -f /etc/lsb-release ]; then
  # Install Utimaco simulator and run tests
  bash .github/reusable_scripts/test_utimaco.sh

  # Test HSM package directly
  # shellcheck disable=SC2086
  cargo test -p cosmian_cli --target "$TARGET" $RELEASE -- test_all_hsm_cli --ignored
fi
