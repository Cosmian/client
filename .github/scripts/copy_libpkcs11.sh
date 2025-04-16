#!/bin/bash

set -ex

docker stop lib_pkcs11 || true
docker rm lib_pkcs11 || true
docker rmi libpkcs11_buster || true
docker buildx build --progress=plain --platform linux/amd64 -t libpkcs11_buster .

docker run --rm --name lib_pkcs11 -d libpkcs11_buster tail -f /dev/null
sleep 5

docker cp lib_pkcs11:/usr/bin/libcosmian_pkcs11.so .

# SSH config:
# Host okv
#     HostName 192.168.1.210
#     User cosmian
#     IdentityFile ~/.ssh/id_rsa

# Copy the library to the OKV server
scp libcosmian_pkcs11.so okv:
ssh okv "sudo cp ~/libcosmian_pkcs11.so /usr/local/okv/hsm/generic/"
ssh okv "sudo chown oracle:oinstall /usr/local/okv/hsm/generic/libcosmian_pkcs11.so"
ssh okv "sudo rm -f /var/okv/log/hsm/*"

#
# Copy CLI config
#
scp crate/pkcs11/oracle/cosmian.toml okv:
ssh okv "sudo mv ~/cosmian.toml /usr/local/okv/hsm/generic"
ssh okv "sudo chown oracle:oinstall /usr/local/okv/hsm/generic/cosmian.toml"

#
# Copy OKV generic HSM variables env. file
#
scp crate/pkcs11/oracle/okv_hsm_env okv:
ssh okv "sudo mv ~/okv_hsm_env /usr/local/okv/hsm/generic/okv_hsm_env"
ssh okv "sudo chown oracle:oinstall /usr/local/okv/hsm/generic/okv_hsm_env"

#
# Copy OKV generic HSM config file
#
scp crate/pkcs11/oracle/okv_hsm_conf okv:
ssh okv "sudo mv ~/okv_hsm_conf /usr/local/okv/hsm/generic/okv_hsm_conf"
ssh okv "sudo chown oracle:oinstall /usr/local/okv/hsm/generic/okv_hsm_conf"
