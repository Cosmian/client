#!/bin/bash

set -ex

export KMS_CLI_FORMAT=json
SEED="11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF"
COSMIAN="cargo run --bin cosmian --"

# Create the key encryption key
kek_id=$($COSMIAN kms sym keys create | jq -r '.unique_identifier')
echo "kek_id: $kek_id"

# Create the index ID
index_id=$($COSMIAN findex-server permissions create | sed 's/Created Index ID: //')
echo "index_id: $index_id"

# Encrypt and index the data
$COSMIAN findex-server encrypt-and-index --seed $SEED --index-id "$index_id" --kek-id "$kek_id" --csv test_data/datasets/smallpop.csv

# Search and decrypt the data
expected_line=$($COSMIAN findex-server search-and-decrypt --seed $SEED --index-id "$index_id" --kek-id "$kek_id" --keyword "Southborough" | sed 's/Decrypted records: //')
echo "expected_line: $expected_line"

# Check the result
if [[ "$expected_line" != "[\"SouthboroughMAUnited States9686\"]" ]]; then
  echo "Test failed: unexpected result"
  exit 1
else
  echo "Test passed"
  exit 0
fi
