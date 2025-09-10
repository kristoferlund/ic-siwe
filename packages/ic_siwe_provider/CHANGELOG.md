# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2025-09-10

### Breaking Changes

- **Authentication Required**: All SIWE authentication endpoints (`siwe_prepare_login`, `siwe_login`, and `siwe_get_delegation`) now require authenticated (non-anonymous) calls to enhance security. This ensures that only the user who initiated the sign-in flow can complete it. Anonymous principals are no longer allowed to make calls to these endpoints.
- **Nonce Handling Changed**:
  - `siwe_prepare_login` now returns only the SIWE message string directly, not an object containing the message and nonce
  - `siwe_login` no longer accepts a `nonce` parameter

### Security Enhancements

- Store sign-in messages under hash(address, principal) instead of just address to ensure only the user that initiated the login flow can sign in.
- Added `ensure_authenticated` guard function to enforce authentication requirements throughout the authentication flow.

### Changed

- Updated `get_caller_address` to require authenticated calls (non-anonymous principal).

### Dependencies

- Updated `ic-cdk` to 0.18.7
- Updated `candid` to 0.10.9
- Updated `ic-stable-structures` to 0.7.0
- Updated `ethers` to 2.0.14
- Updated various other dependencies to their latest versions for improved performance and security

## [0.1.1] - 2024-08-28

### Changed

- Updated dependencies: ic-cdk

## [0.1.0] - 2024-08-22

This is a breaking change release that changes the call signatures and results of the `siwe_prepare_login` and `siwe_login` methods. The `nonce` feature flag has been deprecated in the `ic_siwe` library. Nonces are now generated for all SIWE messages by default. This change increases the security of the login flow.

### Added
- [Secure generated SIWE messages using nonce](https://github.com/kristoferlund/ic-siwe/commit/0b1118b822201b5bb124cfc0bd505a3c9550e29a)

## [0.0.7] - 2024-07-05

### Changed

- Updated dependencies: candid, ic-cdk, ic-stable-structures

## [0.0.6] - 2024-03-25

### Added

- Runtime features that allow for customization of the provider canister behavior: `IncludeUriInSeed`, `DisableEthToPrincipalMapping` and `DisablePrincipalToEthMapping`. See [README.md](./README.md) for details.

## [0.0.5] - 2024-02-22

### Fixed

- Pre-built provider canister did not include metadata, now fixed.

## [0.0.4] - 2024-01-31

### Changed

- Service functions `prepare_login`, `login` and `get_delegation` have been renamed `siwe_prepare_login`, `siwe_login` and `siwe_get_delegation` respectively. See [ic_siwe_provider.did](./ic_siwe_provider.did) for details.

## [0.0.3] - 2024-01-15

- Sync version number with `ic-use-actor` and `ic-use-siwe-identity`.

## [0.0.1] - 2024-01-08

### Added

- First release. `ic_siwe_provider` v0.0.1 should be regarded as alpha software.
