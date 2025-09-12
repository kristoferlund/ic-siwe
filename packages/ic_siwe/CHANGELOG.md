# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-09-10

### Security Enhancements

- Store sign-in messages under hash(address, principal) instead of just address to ensure only the user who initiated the login flow can complete it.
- Requires authenticated principals (caller) to be passed to `prepare_login` and `login` functions to enhance security.

### Changed

- `prepare_login` now requires a `Principal` parameter to associate the sign-in message with the calling principal.
- `prepare_login` returns a `Result` containing the prepared login message or an error. `nonce` is no longer returned as a separate value but is included in the prepared SIWE message.
- `login` function no longer takes `nonce` as a parameter, as it is now only used as part of the SIWE message.
- `login` function validates that the caller is the same as the principal associated with the SIWE message.

### Dependencies

- Updated `ic-cdk` to 0.18.7
- Updated `candid` to 0.10.18
- Updated `ethers` to 2.0.14
- Updated various other dependencies to their latest versions for improved performance and security

## [0.1.1] - 2024-08-28

### Changed

- Updated dependencies: ic-cdk

## [0.1.0] - 2024-08-22

This is a breaking change release that makes the nonce feature standard. The nonce feature is now enabled by default and the `nonce` feature flag is deprecated. This version also includes fixes to increase login flow security.

### Added
- [Secure generated SIWE messages using nonce](https://github.com/kristoferlund/ic-siwe/commit/0b1118b822201b5bb124cfc0bd505a3c9550e29a)

### Changed
- [Make the nonce feature standard](https://github.com/kristoferlund/ic-siwe/commit/3e298fa757ad98b1be4a088358420e2e77cdb128)

### Fixed
- [Return error if signature has expired](https://github.com/kristoferlund/ic-siwe/commit/c4cd84dc3125408100e3f37a1138e4a4cd3b5c2d)
- [Remove stored SIWE message](https://github.com/kristoferlund/ic-siwe/commit/6daf4563f95f4dc653cb717f053e45e2fed578b9)

## [0.0.7] - 2024-07-05

### Changed

- Updated dependencies: candid, ic-cdk, ic-cdk-timers

## [0.0.6] - 2024-03-25

### Added

- Runtime feature flag that allow for customization of the library behavior: `IncludeUriInSeed`. See [settings.rs](./src/settings.rs) for details.

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
