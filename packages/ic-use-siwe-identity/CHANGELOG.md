# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.5] - 2024-01-16

### Fixed

- On address change, reset the state. Action is conditional on state.isInitializing being false.

## [0.0.4] - 2024-01-16

### Added

- `prepareLogin` function. The function loads a SIWE message from the provider canister, to be used for login. Calling prepareLogin is optional, as it will be called automatically on login if not called manually.
- `prepareLoginStatus` state variable. `error` | `loading` | `success` | `idle` - Reflects the current status of the prepareLogin process.
- `prepareLoginError`. Error that occurred during the prepareLogin process.
- `loginStatus` state variable. `error` | `success` | `idle` | `logging-in` - Reflects the current status of the login process.
- `loginError`. Error that occurred during the login process.

## [0.0.3] - 2024-01-15

- Sync version number with `ic-use-acctor`
- Re-export types for nicer looking imports in consuming apps.
- Minify the bundle.

## [0.0.1] - 2024-01-08

### Added

- First release. `ic-use-siwe-identity` v0.0.1 should be regarded as alpha software.
