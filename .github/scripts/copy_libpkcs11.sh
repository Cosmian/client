#!/bin/bash

set -ex

docker stop lib_pkcs11 || true
docker rm lib_pkcs11 || true
docker rmi libpkcs11_buster || true
docker buildx build --progress=plain --platform linux/amd64 -t libpkcs11_buster .

docker run --rm --name lib_pkcs11 -d libpkcs11_buster tail -f /dev/null
sleep 5

docker cp lib_pkcs11:/usr/bin/libcosmian_pkcs11.so .
scp libcosmian_pkcs11.so okv:
ssh okv "sudo cp ~/libcosmian_pkcs11.so /usr/local/okv/hsm/generic/"
ssh okv "sudo rm -f /var/okv/log/hsm/*"
ssh okv "sudo rm -f /var/log/cosmian-pkcs11.log"
ssh okv "sudo touch /var/log/cosmian-pkcs11.log"
ssh okv "sudo chown oracle:oinstall /var/log/cosmian-pkcs11.log"
