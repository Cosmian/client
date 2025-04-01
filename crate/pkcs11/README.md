# This directory provides

- base Rust PKCS#11 bindings and traits that can be used to create a PKCS#11 client or a PKCS#11 provider
- a PKCS#11 library to interface the KMS (the `provider` crate) from a PKCS#11 compliant application such as LUKS

[PKCS##11 documentation](https://www.cryptsoft.com/pkcs11doc/STANDARD/pkcs-11.pdf)

1. `module` crate

    The module crate exposes traits to create a PKCS#11 library. It is a modified fork of
    the `native_pkcs11` crate from Google. The `module` crate is used to build the `provider` PKCS#11 library.

2. `provider` crate

    The provider crate is a PKCS#11 library that interfaces the KMS. It provides a PKCS#11 library that can be used by
    applications such as LUKS to interface the KMS. The `provider` crate is built from the `module` crate.

## Oracle Key Vault integration

Install OVK 21.10
Build libcosmian_pkcs11.so on debian-buster where glibc 2.28 is equal to OVK RHEL system.

```sh
scp libcosmian_pkcs11.so /usr/local/okv/hsm/generic/
Edit /usr/local/okv/hsm/generic/okv_hsm.conf

```sh
[root@okv080027c5c0eb hsm]# cat /usr/local/okv/hsm/generic/okv_hsm.conf
# Oracle Key Vault HSM vendor configuration file
# Lines must be shorter than 4096 characters.

# The vendor name, to be displayed on the HSM page on the management console.
VENDOR_NAME="cosmian"

# The location of the PKCS#11 library. This file must be preserved on upgrade.
PKCS11_LIB_LOC="/usr/local/okv/hsm/generic/libcosmian_pkcs11.so"

# A colon-separated list of the full paths of files and directories that must
# be preserved on upgrade. All of these files and directories should have been
# created by the HSM client software setup; none should have existed on Oracle
# Key Vault by default. These will be necessary when upgrading to a version
# of Oracle Key Vault that is running on a higher major OS version.
# Do not use wildcards.
PRESERVED_FILES=""
````

Edit /usr/local/okv/hsm/generic/okv_hsm_env

```sh
[root@okv080027c5c0eb hsm]# cat /usr/local/okv/hsm/generic/okv_hsm_env
# Oracle Key Vault HSM vendor environment file
# Use this file to set any necessary environment variables needed when using
# a vendor's PKCS#11 library. Parameter names must not contain '='.
# Parameter values must be enclosed in double quotes. Names and values must
# be shorter than 4096 characters.

# Below is an example. Remove the '#' character to uncomment the line.
#EXAMPLE_ENV_VAR_NAME="EXAMPLE_ENV_VAR_VALUE"
COSMIAN_PKCS11_LOGGING_LEVEL="trace"
```

Read the logs on /var/okv/log/hsm/...

`oracle` user needs to be able to write to /var/log/cosmian-pkcs11.log

```sh
chown oracle:oracle /var/log/cosmian-pkcs11.log
chmod 664 /var/log/cosmian-pkcs11.log
```

Configure the Cosmian CLI configuration for oracle user (/home/oracle/.cosmian/config.toml):

```sh
[kms_config.http_config]
server_url = "http://192.168.1.17:9998"

[findex_config.http_config]
server_url = "http://0.0.0.0:6668"
```

Initialize the HSM in Oracle Key Vault:
    Go to UI->System->Settings->HSM
    Click on Initialize button

You should have:

```text
[root@okv080027c5c0eb ~]# cat /var/okv/log/hsm/*
2025-03-26 14:55:02.122: Beginning trace for hsmclient pre_restore
2025-03-26 14:55:02.122: Loading /usr/local/okv/hsm/generic/okv_hsm_env
2025-03-26 14:55:02.122: Setting COSMIAN_PKCS11_LOGGING_LEVEL to trace
2025-03-26 14:55:02.122: Setting COSMIAN_CLI_CONF to /home/oracle/.cosmian/cosmian.toml
2025-03-26 14:55:02.123: WARNING: skipping line 11 with invalid formatting
2025-03-26 14:55:02.123: Setting path
2025-03-26 14:55:02.123: No token label provided
2025-03-26 14:55:02.123: Loading PKCS11 library: /usr/local/okv/hsm/generic/libcosmian_pkcs11.so
2025-03-26 14:55:02.147: Writing HSM credential from user input
2025-03-26 14:55:02.147: Creating the HSM credential wallet...
Oracle PKI Tool Release 19.0.0.0.0 - Production
Version 19.4.0.0.0
Copyright (c) 2004, 2024, Oracle and/or its affiliates. All rights reserved.

Operation is successfully completed.
2025-03-26 14:55:04.046: Created the HSM credential wallet
2025-03-26 14:55:04.047: Proceeding with FIPS enabled for HSM
2025-03-26 14:55:04.148: Finished writing HSM credential
2025-03-26 14:55:04.148: Checking for HSM credential...
2025-03-26 14:55:04.148: Retrieving the HSM credential...
2025-03-26 14:55:04.148: Proceeding with FIPS enabled for HSM
2025-03-26 14:55:04.216: Retrieved the HSM credential
2025-03-26 14:55:04.216: HSM credential found
2025-03-26 14:55:04.216: Connecting to HSM...
2025-03-26 14:55:04.216: Connecting to the HSM...
2025-03-26 14:55:04.216: Not using token label to choose slot, defaulting to first in slot list
2025-03-26 14:55:04.216: Connected to the HSM
2025-03-26 14:55:04.216: Connection to HSM succeeded
2025-03-26 14:55:04.216: Checking HSM setting in configuration file
2025-03-26 14:55:04.216: HSM enabled in configuration file
2025-03-26 14:55:04.216: Getting encryption key metadata...
2025-03-26 14:55:04.216: Verifying header...
2025-03-26 14:55:04.216: Header version: 0x18010000
2025-03-26 14:55:04.216: HSM Root of Trust key number: 281109417
2025-03-26 14:55:04.216: Header verified
2025-03-26 14:55:04.216: Retrieved encryption key metadata
2025-03-26 14:55:04.216: Searching for root of trust in HSM...
2025-03-26 14:55:04.216: Getting the Root of Trust key...
2025-03-26 14:55:04.245: Retrieved 1 keys
2025-03-26 14:55:04.245: Retrieved Root of Trust key handle: 0
2025-03-26 14:55:04.245: Found root of trust in HSM
2025-03-26 14:55:04.245: Checking that we can decrypt the encrypted TDE password...
2025-03-26 14:55:04.245: Decrypting data...
2025-03-26 14:55:04.280: Finished decrypting data
2025-03-26 14:55:04.280: Able to decrypt the TDE password.
2025-03-26 14:55:04.280: Checking that the TDE password is correct...
2025-03-26 14:55:04.280: Checking the wallet password...
2025-03-26 14:55:05.853: Checked the wallet password
2025-03-26 14:55:05.853: TDE password is correct.
2025-03-26 14:55:05.853: Checking password for the restore wallet...
2025-03-26 14:55:05.853: Checking the wallet password...
2025-03-26 14:55:07.506: Checked the wallet password
2025-03-26 14:55:07.506: Restore wallet password is correct.
2025-03-26 14:55:07.506: Checking wallet links
2025-03-26 14:55:07.506: Verified wallet links
2025-03-26 14:55:07.506: HSM configuration verified
2025-03-26 14:55:07.506: Disconnecting from the HSM...
2025-03-26 14:55:07.506: Disconnected from the HSM
2025-03-26 14:55:07.561: Unloading PKCS11 library
2025-03-26 14:55:07.561: Finished successfully
Cosmian PKCS#11 provider: C_GetFunctionList called
cosmian-pkcs11 module logging at TRACE level to file /var/log/cosmian-pkcs11.log
Enter HSM credential:
Reenter HSM credential:
```
