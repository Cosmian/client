#!/bin/bash

set -ex

OLD_VERSION="$1"
NEW_VERSION="$2"

# Use SED_BINARY from environment if set, otherwise default to 'sed'
# On MacOs - install gnu-sed with brew
SED_BINARY=${SED_BINARY:-sed}

SED() {
  args=$1
  file=$2
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # echo "Not Linux"
    $SED_BINARY -i '' "${args}" "$file"
  else
    # echo "Linux"
    $SED_BINARY -i "${args}" "$file"
  fi
}

SED "s/$OLD_VERSION/$NEW_VERSION/g" Cargo.toml
SED "s/$OLD_VERSION/$NEW_VERSION/g" crate/cli/Cargo.toml
SED "s/$OLD_VERSION/$NEW_VERSION/g" crate/pkcs11/provider/Cargo.toml

# Other files
SED "s/$OLD_VERSION/$NEW_VERSION/g" Dockerfile
SED "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/index.md
SED "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/installation.md
SED "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/pkcs11/oracle/tde.md

cargo build
git cliff -w "$(pwd)" -u -p CHANGELOG.md -t "$NEW_VERSION"
