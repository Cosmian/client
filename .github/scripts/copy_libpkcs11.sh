#!/bin/bash

set -ex

# docker stop lib_pkcs11 || true
# docker rm lib_pkcs11 || true
# docker rmi libpkcs11_buster || true
# docker buildx build --progress=plain --platform linux/amd64 -t libpkcs11_buster .

# docker run --rm --name lib_pkcs11 -d libpkcs11_buster tail -f /dev/null
# sleep 5

docker cp lib_pkcs11:/usr/bin/libcosmian_pkcs11.so .
scp libcosmian_pkcs11.so okv:
ssh okv "sudo cp ~/libcosmian_pkcs11.so /usr/local/okv/hsm/generic/"
ssh okv "sudo rm -f /var/okv/log/hsm/*"
ssh okv "sudo rm -f /var/log/cosmian-pkcs11.log"
ssh okv "sudo touch /var/log/cosmian-pkcs11.log"
ssh okv "sudo chown oracle:oinstall /var/log/cosmian-pkcs11.log"

#
# Copy CLI config
#
cat >config.toml <<'EOF'
[kms_config.http_config]
server_url = "http://192.168.1.17:9998"

[findex_config.http_config]
server_url = "http://0.0.0.0:6668"
EOF

scp config.toml okv:
ssh okv "sudo mkdir -p /home/oracle/.cosmian && sudo mv ~/config.toml /home/oracle/.cosmian/ && sudo chown -R oracle:oinstall /home/oracle/.cosmian"

#
# Copy OKV generic HSM variables env. file
#
cat >hsm_env <<'EOF'
# Oracle Key Vault HSM vendor environment file
# Use this file to set any necessary environment variables needed when using
# a vendor's PKCS#11 library. Parameter names must not contain '='.
# Parameter values must be enclosed in double quotes. Names and values must
# be shorter than 4096 characters.

# Below is an example. Remove the '#' character to uncomment the line.
#EXAMPLE_ENV_VAR_NAME="EXAMPLE_ENV_VAR_VALUE"
COSMIAN_PKCS11_LOGGING_LEVEL="trace"
COSMIAN_CLI_CONF="/home/oracle/.cosmian/cosmian.toml"
EOF

scp hsm_env okv:
ssh okv "sudo mv ~/hsm_env /usr/local/okv/hsm/generic/okv_hsm_env"

#
# Copy OKV generic HSM config file
#
cat >hsm_conf <<'EOF'
# Oracle Key Vault HSM vendor configuration file
# Lines must be shorter than 4096 characters.

# The vendor name, to be displayed on the HSM page on the management console.
VENDOR_NAME="Cosmian"

# The location of the PKCS#11 library. This file must be preserved on upgrade.
PKCS11_LIB_LOC="/usr/local/okv/hsm/generic/libcosmian_pkcs11.so"

# A colon-separated list of the full paths of files and directories that must
# be preserved on upgrade. All of these files and directories should have been
# created by the HSM client software setup; none should have existed on Oracle
# Key Vault by default. These will be necessary when upgrading to a version
# of Oracle Key Vault that is running on a higher major OS version.
# Do not use wildcards.
PRESERVED_FILES=""
EOF

scp hsm_conf okv:
ssh okv "sudo mv ~/hsm_conf /usr/local/okv/hsm/generic/okv_hsm.conf"
