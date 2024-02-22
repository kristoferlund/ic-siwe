# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.5] - 2024-02-22

### Fixed

- Pre-built provider canister did not include metadata, now fixed.

## [0.0.4] - 2024-01-31

Aligning version numbers with [ic_siwe_provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider)

### Added

- `EthAddress` and `EthSignature` structs for type safety.
- Added basic validation of delegation targets. Duplicate targets are now rejected.

### Changed
- Library functions now mostly returns custom error types instead of strings. As a result, many error messages now differ slighlty to previous version.
- `prepare_login` and `login` now requires `EthAddress` and `EthSignature` structs instead of strings.
- Replaced `create_user_canister_pubkey` with a more readable implementation.


##

## [0.0.1] - 2024-01-23

### Added

- First release. `ic_siwe` v0.0.1 should be regarded as alpha software.
