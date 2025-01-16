# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2024-10-22

### Fixed

- State management bug preventing login to complete under certain conditions.

## [0.1.1] - 2024-10-21

### Changed

- Allow 2.x.x versions of dfinity dependencies

## [0.1.0] - 2024-08-22

**This is a breaking change release**

Minimum `ic_siwe_provider` canister required is v0.1.0.

This version improves the security and reliability of the SIWE (Sign-In with Ethereum) process by ensuring proper cleanup of SIWE messages, implementing nonce-based security measures, and validating signature expiration. These changes help prevent replay attacks and ensure that expired signatures are not accepted.

More info: <https://github.com/kristoferlund/ic-siwe/releases/tag/v0.1.0>

### Changed

- Upgraded hook to match new call signatures for SIWE provider canister functions.
- Upgraded dependencies, hook now requires at least v1.4.0 of @dfifnity libraries.
- chore: Switched from npm to pnpm for package management.

## [0.0.11] - 2024-03-19

### Fixed

- A state handling bug prevented the promise returned by login() from working on first call to function.

## [0.0.10] - 2024-03-18

### Changed

- The `login` function now returns a `Promise` that resolves to the `Identity` of the logged in user. New signature: `login: () => Promise<DelegationIdentity | undefined>`.
- Upgraded wagmi to v2.5.7.
  - This introduces TanStack Query as an additional dependency.
  - Also, this means the signture for `signMessageStatus` has changed slightly to `signMessageStatus: "error" | "idle" | "pending" | "success"`.
- Upgraded viem to v2.8.4

## [0.0.9] - 2024-03-07

### Changed

- Moved @dfinity/xxx dependencies from dependencies to peerDependencies to reduce package size.

## [0.0.8] - 2024-03-07

### Changed

- Upgraded @dfinity/xxx dependencies to latest versions.

## [0.0.7] - 2021-10-31

### Added

- Added prepare login and login status flags to SiweIdentityContextType for convenience.

```
  isPreparingLogin: state.prepareLoginStatus === "preparing",
  isPrepareLoginError: state.prepareLoginStatus === "error",
  isPrepareLoginSuccess: state.prepareLoginStatus === "success",
  isPrepareLoginIdle: state.prepareLoginStatus === "idle",
  isLoggingIn: state.loginStatus === "logging-in",
  isLoginError: state.loginStatus === "error",
  isLoginSuccess: state.loginStatus === "success",
  isLoginIdle: state.loginStatus === "idle",
```

### Changed

- `prepareLoginStatus: "loading"` changed to `prepareLoginStatus: "preparing"` for consistency with `loginStatus: "logging-in"`.
-

## [0.0.6] - 2024-01-18

### Changed

- Moved @dfinity/xxx dependencies from peerDependencies to dependencies because of bundling issues. This grows package size but prevents bundling issues in consuming apps.
- Minor refactoring.

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
