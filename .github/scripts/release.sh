#!/bin/sh

set -ex

OLD_VERSION="$1"
NEW_VERSION="$2"

sed -i "s/$OLD_VERSION/$NEW_VERSION/g" Cargo.toml
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" Dockerfile
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/index.md
sed -i "s/$OLD_VERSION/$NEW_VERSION/g" documentation/docs/installation.md

sed -i "s/$OLD_VERSION/$NEW_VERSION/g" cli/ui/package.json

cargo build
git cliff -u -p CHANGELOG.md -t "$NEW_VERSION"
