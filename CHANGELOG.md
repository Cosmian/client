# Changelog

All notable changes to this project will be documented in this file.

## [1.7.1] - 2026-01-21

### 🚀 Features

- Bump KMS to 5.14.1

### ⚙️ Miscellaneous Tasks

- Fix cargo deny upgrade (#124)

## [1.7.0] - 2025-12-15

### 💼 Other

- *(deps)* Bump actions/checkout from 5 to 6 ([#119](https://github.com/Cosmian/cli/pull/119))
- *(deps)* Bump actions/upload-artifact from 5 to 6 ([#123](https://github.com/Cosmian/cli/pull/123))

### 🧪 Testing

- Add test on new sign actions ([#122](https://github.com/Cosmian/cli/pull/122))

## [1.6.0] - 2025-12-08

### 🚀 Features

- KMS CLI additions aligned with KMIP XML vectors:
  - `rng retrieve` and `rng seed` for RNG operations
  - `mac verify` to validate message authentication codes
  - `discover-versions` and `query` for KMIP discovery and server queries
- Opaque Object subcommands:
  - `opaque-object create`, `import`, `export` (raw/base64/json), `revoke`, `destroy`
- Attributes:
  - Deterministic `attributes get` ordering aligned with server
  - Expanded attribute flows consistent with KMIP GetAttributeList/ModifyAttribute

### 🧪 Testing

- Added CLI tests: Opaque Object CRUD, RNG Retrieve/Seed, MAC Verify, Query, DiscoverVersions.

### 📚 Documentation

- Updated CLI docs/examples to reflect new subcommands and attribute behavior.

## [1.5.2] - 2025-11-19

### 🐛 Bug Fixes

- Google key pair remove sanity check - moved to server ([#118](https://github.com/Cosmian/cli/pull/118))

### 🚀 Features

- Add parameter `--days` to configure the certificate expiration date on google key-pair create command ([#118](https://github.com/Cosmian/cli/pull/118))

### 💼 Other

- *(deps)* Bump actions/upload-artifact from 4 to 5 ([#117](https://github.com/Cosmian/cli/pull/117))

## [1.5.1] - 2025-10-28

### 🐛 Bug Fixes

- *(google_cse)* Load RSA private as PKCS8 or PKCS1 format ([#592](https://github.com/Cosmian/cli/pull/592))

### ⚠️ WARNING

**Gmail CSE users:** Versions 1.3/1.4 and 1.5.0 contain a blocking issue with Gmail Client-Side Encryption support (issue loading PKCS#8 RSA private key). Please upgrade to version 1.5.1 or later to ensure proper Gmail CSE functionality.

## [1.5.0] - 2025-10-22

### 🚀 Features

- Support wrapping SecretData object ([#109](https://github.com/Cosmian/cli/pull/109))
- Add derive key subcommand ([#111](https://github.com/Cosmian/cli/pull/111))
- Create a configuration wizard - add configure subcommand ([#116](https://github.com/Cosmian/cli/pull/116))

### 🐛 Bug Fixes

- Build errors

### 🧪 Testing

- Add luks integration script ([#108](https://github.com/Cosmian/cli/pull/108))

### ⚙️ Miscellaneous Tasks

- Configure Dependabot for GitHub Actions updates
- Add SECURITY.md file ([#113](https://github.com/Cosmian/cli/pull/113))
- Use cosmian_logger ([#110](https://github.com/Cosmian/cli/pull/110))
- Split cargo_build.sh into multiple files ([#114](https://github.com/Cosmian/cli/pull/114))

### Build

- *(deps)* Bump actions/checkout from 4 to 5 ([#112](https://github.com/Cosmian/cli/pull/112))

## [1.4.1] - 2025-09-16

### 🐛 Bug Fixes

- Re-publish `cosmian_cli` crate without direct dependency on `test_kms_server` (only dev-dependency)

## [1.4.0] - 2025-09-16

### 🚀 Features

- *CLI*: Added support for SHA1 in RSA key wrapping and add Azure functionality to facilitate BYOK ([#105](https://github.com/Cosmian/cli/pull/105))

### 🐛 Bug Fixes

- *PKCS11*: Skip unknown key types in search functions (find_*) and update KMS and FS crates ([#104](https://github.com/Cosmian/cli/pull/104))
- Deliver CLI with all features - including non-FIPS feature

## [1.3.0] - 2025-08-22

### 🚀 Features

- Add support for Oracle TDE with direct HSM/KMS connection ([#89](https://github.com/Cosmian/cli/pull/89))
- *(Google CSE)* Consume KMS Google Key pair action ([#100](https://github.com/Cosmian/cli/pull/100))
- Support HTTP forward proxy ([#102](https://github.com/Cosmian/cli/pull/102))
- Create comprehensive .github/copilot-instructions.md with validated build procedures and OpenSSL 3.2.0 requirements ([#94](https://github.com/Cosmian/cli/pull/94))

### 🐛 Bug Fixes

- RUSTSEC-2025-0047: Update slab dependency from 0.4.10 to 0.4.11 ([#92](https://github.com/Cosmian/cli/pull/92))
- README.md: remove UI section and correct formatting issues ([#96](https://github.com/Cosmian/cli/pull/96))

### ⚙️ Miscellaneous Tasks

- Fix publish step
- Skip debug pipeline on tags
- Fix audit GitHub action ([#99](https://github.com/Cosmian/cli/pull/99))

## [1.2.0] - 2025-08-08

### 🚀 Features

- Upgrade findex to v8 and clean some dependency import paths ([#87](https://github.com/Cosmian/cli/pull/87))

### 🐛 Bug Fixes

- Rocky package must be NON-FIPS ([#83](https://github.com/Cosmian/cli/pull/83))
- Reduce binaries size (EXE and DLL) ([#84](https://github.com/Cosmian/cli/pull/84))

### 📚 Documentation

- Add updated google key-pairs create command ([#76](https://github.com/Cosmian/cli/pull/76))

### ⚙️ Miscellaneous Tasks

- Replace test_data folder with git submodule ([#86](https://github.com/Cosmian/cli/pull/86))

## [1.1.0] - 2025-07-23

### 🚀 Features

- Handle Secret Data

## [1.0.0] - 2025-07-08

### 🚀 Features

- Invert fips feature
- Handle extension file to define x509 setup extensions for Google CSE keypairs create command

### ⚙️ Miscellaneous Tasks

- Display items ID on google keypairs creation command

### 🧪 Testing

- Test with stackoverflow

## [0.5.0] - 2025-06-04

### 🚀 Features

- Support sqlite3 as database type ([#61](https://github.com/Cosmian/cli/pull/61))
- Allow KMS/Findex source code edition while modifying CLI ([#65](https://github.com/Cosmian/cli/pull/65))

### 🐛 Bug Fixes

- Clap short duplicate ([#67](https://github.com/Cosmian/cli/pull/67))

### 🚜 Refactor

- Remove client-crates and consume clap actions instead ([#64](https://github.com/Cosmian/cli/pull/64))

## [0.4.1] - 2025-05-22

### 🚀 Features

- Display user_id in the Header UI to help users identify their session context
- Update server test configuration to align with changes introduced in version 5.1.0
- Support for PKCE (Proof Key for Code Exchange) authentication from the CLI with the Cosmian KMS
- Concurrent multi factor authentication with clear cascading rules (OIDC / Client Certificates / API TOken)

### 🐛 Bug Fixes

- Fix Revoke structure on UI for key revocation
- Unclear cascading rules in multi-factor authentication

### 📚 Documentation

- PKCE documentation with configuration examples
- Improved authentication documentation both client and server side

## [0.4.0] - 2025-05-09

### 🚀 Features

- Run KMS server with privileged users ([#40](https://github.com/Cosmian/cli/pull/40)):
  - These users can grant or revoke access rights for other users
- Support Kmip 1 ([#48](https://github.com/Cosmian/cli/pull/48))

### 🐛 Bug Fixes

- Cargo deny missing license

### 🚜 Refactor

- MemoryADT implementation for KmsEncryptionLayer ([#46](https://github.com/Cosmian/cli/pull/46))

### 📚 Documentation

- From RHEL to Rocky Linux URL update

### ⚙️ Miscellaneous Tasks

- Reuse GitHub workflow to publish artifacts
- Centralize subcrates version in root Cargo.toml ([#55](https://github.com/Cosmian/cli/pull/55))
- Missing Cargo.toml descriptions

## [0.3.1] - 2025-04-24

### 🚀 Features

- Add Oracle Key Vault integration ([#24](https://github.com/Cosmian/cli/pull/24))

### ⚙️ Miscellaneous Tasks

- Fix missing attached assets on GH release
- Use cosmian published crates

## [0.3.0] - 2025-04-10

### 🚀 Features

- Delegates encryption to KMS ([#13](https://github.com/Cosmian/cli/pull/13))
- Add UI in React + WASM ([#21](https://github.com/Cosmian/cli/pull/21))
- Add CBC mode support for KMS encryption ([#23](https://github.com/Cosmian/cli/pull/23))

### 🐛 Bug Fixes

- Test_kms_client: bug when exporting a sym key using the tag of a private key
- Test_certificate_encrypt_using_rsa: add prefix to temporary files
- RUSTSEC-2025-0022: Use-After-Free in Md::fetch and Cipher::fetch
- Findex concurrent tests on KMS encryption layer

### 🚜 Refactor

- Import all KMS CLI crates ([#18](https://github.com/Cosmian/cli/pull/18))

### ⚙️ Miscellaneous Tasks

- Missing artifact libcosmian_pkcs11.so on RHEL
- Reuse generic GitHub workflows

## [0.2.0] - 2025-02-04

### 🚀 Features

- Support Findex server v0.2 (including findex v7) ([#9](https://github.com/Cosmian/cli/pull/9))

### 📚 Documentation

- Edit authentication section ([#7](https://github.com/Cosmian/cli/pull/7))

### 🧪 Testing

- Run all tests on ubuntu runners

## [0.1.3] - 2025-01-09

### 🧪 Testing

- Reuse clap actions instead of cosmian binary

## [0.1.2] - 2024-12-23

### 📚 Documentation

- Fix notes in README
- Add KMS, FS correspondence versions
- Simplify configuration examples

## [0.1.1] - 2024-12-17

### 🐛 Bug Fixes

- Save cli configuration if login/logout have been called ([#4](https://github.com/Cosmian/cli/pull/4))

### 📚 Documentation

- Fix typo

## [0.1.0] - 2024-12-04

### 🚀 Features

- Create cosmian CLI
- Encrypt datasets, add indexes, search keywords and decrypt results
- Delete dataset + reuse config_utils crate

### 📚 Documentation

- Integrate KMS `ckms` documentation
- Add authorization (move from KMS)

### 🧪 Testing

- Using docker container to provide KMS and Findex server

<!-- generated by git-cliff -->
