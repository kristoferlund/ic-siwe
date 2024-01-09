# ic-siwe

The `ic-siwe` project facilitates the integration of Ethereum wallet-based authentication with applications on the Internet Computer (IC) platform.

`ic-siwe` enhances the interoperability between Ethereum and the Internet Computer platform, enabling developers
to build applications that leverage the strengths of both platforms.

## Key Features

- **Ethereum Wallet Sign-In**: Enables Ethereum wallet sign-in for IC applications. Sign in with any eth wallet to generate an IC identity and session.
- **Session Identity Uniqueness**: Ensures that session identities are specific to each application's context, preventing cross-app identity misuse.
- **Consistent Principal Generation**: Guarantees that logging in with an Ethereum wallet consistently produces the same Principal, irrespective of the client used.
- **Direct Ethereum Address to Principal Mapping**: Creates a one-to-one correlation between Ethereum addresses and Principals within the scope of the current application.
- **Timebound Sessions**: Allows developers to set expiration times for sessions, enhancing security and control.
- **Prebuilt Identity Provider**: Provides a prebuilt canister that can be integrated into any Internet Computer application, independent of the application's programming language.

The project consists of several packages:

## [ic_siwe](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe)

Rust library that provides the necessary tools for integrating Sign-In with Ethereum (SIWE) into IC canisters, allowing users to sign in using their Ethereum wallets.

## [ic-siwe-provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider)

Prebuilt canister serving as a SIWE identity provider for Internet Computer canisters. `ic_siwe-provider` packages the `ic_siwe` library and makes it available as a canister that can easily be integrated into any Internet Computer application, independent of the application's programming language.

## [ic-use-siwe-identity](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic-use-siwe-identity)

React hook and context provider for easy frontend integration with SIWE enabled Internet Computer canisters.

## [ic-siwe-react-demo-rust](https://github.com/kristoferlund/ic-siwe-react-demo-rust)

React demo application that demonstrates how to integrate SIWE into an Internet Computer canister using the [ic-use-siwe-identity](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic-use-siwe-identity) hook and [ic-siwe-provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider) canister.

The deployed demo can also be accessed here: https://shtr2-2iaaa-aaaal-qckva-cai.icp0.io

## Updates

See the respective package CHANGELOG for details on updates.

## Contributing

Contributions are welcome. Please submit your pull requests or open issues to propose changes or report bugs.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
