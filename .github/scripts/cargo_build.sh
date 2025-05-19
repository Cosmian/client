#!/bin/bash

set -ex

# --- Declare the following variables for tests
# export TARGET=x86_64-unknown-linux-gnu
# export TARGET=aarch64-apple-darwin
# export DEBUG_OR_RELEASE=debug
# export OPENSSL_DIR=/usr/local/openssl
# export SKIP_SERVICES_TESTS="--skip hsm"
# export FEATURES="fips"

ROOT_FOLDER=$(pwd)

# Build UI
if [ -f /etc/lsb-release ]; then
  bash .github/scripts/build_ui.sh
fi

if [ "$DEBUG_OR_RELEASE" = "release" ]; then
  # First build the Debian and RPM packages. It must come at first since
  # after this step `cosmian` and `cosmian_gui` are built with custom features flags (fips for example).
  rm -rf target/"$TARGET"/debian
  rm -rf target/"$TARGET"/generate-rpm
  cargo build --target "$TARGET" --release
  if [ -f /etc/redhat-release ]; then
    cargo install --version 0.16.0 cargo-generate-rpm --force
    cargo generate-rpm --target "$TARGET" -p crate/cli
  elif [ -f /etc/lsb-release ]; then
    cargo install --version 2.4.0 cargo-deb --force
    cargo deb --target "$TARGET" -p cosmian_cli
  fi
fi

if [ -z "$TARGET" ]; then
  echo "Error: TARGET is not set."
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

if [ -z "$SKIP_SERVICES_TESTS" ]; then
  echo "Info: SKIP_SERVICES_TESTS is not set."
  unset SKIP_SERVICES_TESTS
fi

rustup target add "$TARGET"

if [ -f /etc/lsb-release ]; then
  bash .github/scripts/test_utimaco.sh
fi

cd "$ROOT_FOLDER"

if [ -z "$OPENSSL_DIR" ]; then
  echo "Error: OPENSSL_DIR is not set."
  exit 1
fi

# shellcheck disable=SC2086
cargo build --target $TARGET $RELEASE

TARGET_FOLDER=./target/"$TARGET/$DEBUG_OR_RELEASE"
"${TARGET_FOLDER}"/cosmian -h
"${TARGET_FOLDER}"/cosmian_gui -h

if [ "$(uname)" = "Linux" ]; then
  ldd "${TARGET_FOLDER}"/cosmian | grep ssl && exit 1
  ldd "${TARGET_FOLDER}"/cosmian_gui | grep ssl && exit 1
else
  otool -L "${TARGET_FOLDER}"/cosmian | grep openssl && exit 1
  otool -L "${TARGET_FOLDER}"/cosmian_gui | grep openssl && exit 1
fi

find . -type d -name cosmian-findex-server -exec rm -rf \{\} \; -print || true
rm -f /tmp/*.json /tmp/*.toml

export RUST_LOG="fatal,cosmian_cli=error,cosmian_findex_client=debug,cosmian_kmip=error,cosmian_kms_client=debug"

# declare -a DATABASES=('redis-findex' 'sqlite-findex')
# for KMS_TEST_DB in "${DATABASES[@]}"; do
#   echo "Database Findex: $KMS_TEST_DB"

#   # no docker containers on macOS Github runner
#   if [ "$(uname)" = "Darwin" ] && [ "$KMS_TEST_DB" != "sqlite" ]; then
#     continue
#   fi

#   # only tests all databases on release mode - keep sqlite for debug
#   if [ "$DEBUG_OR_RELEASE" = "debug" ] && [ "$KMS_TEST_DB" != "sqlite" ]; then
#     continue
#   fi

#   export KMS_TEST_DB="$KMS_TEST_DB"
#   export SKIP_SERVICES_TESTS="--skip hsm"

#   cargo test --workspace --lib --target --target $TARGET $RELEASE $FEATURES -- --nocapture $SKIP_SERVICES_TESTS
# done

cargo install --version 0.6.36 cargo-hack --force

# shellcheck disable=SC2086
cargo hack test --all --lib --target $TARGET $RELEASE $FEATURES -- --nocapture $SKIP_SERVICES_TESTS
