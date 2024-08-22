![Sign in with Ethereum for the Internet Computer](/media/header.png)

`ic-siwe` is a project that enables Ethereum wallet-based authentication for applications on the [Internet Computer](https://internetcomputer.org) (IC) platform. The goal of the project is to enhance the interoperability between Ethereum and the Internet Computer platform, enabling developers to build applications that leverage the strengths of both platforms.

## Features

- **Ethereum Wallet Sign-In**: Enables Ethereum wallet sign-in for IC applications. Sign in with any eth wallet to generate an IC identity and session.

- **Session Identity Uniqueness**: Ensures that session identities are specific to each application's context, preventing cross-app identity misuse.

- **Consistent Principal Generation**: Guarantees that logging in with an Ethereum wallet consistently produces the same Principal, irrespective of the client used.

- **Direct Ethereum Address to Principal Mapping**: Creates a one-to-one correlation between Ethereum addresses and Principals within the scope of the current application.

- **Timebound Sessions**: Allows developers to set expiration times for sessions, enhancing security and control.

- **Prebuilt Identity Provider**: Provides a prebuilt canister that can be integrated into any Internet Computer application, independent of the application's programming language.

See this video from the ICP Chain Fusion Hackathon for an overview as well as a deep dive how the SIWE flow works:
[![Integrating with SIWE & SIWS](https://img.youtube.com/vi/lQV4Otp6Y_s/0.jpg)](https://www.youtube.com/watch?v=lQV4Otp6Y_s)

## Usage

Developers have two options to use SIWE in their IC applications:

1. **Use the prebuilt [ic_siwe_provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider) canister**: This is the easiest way to integrate SIWE into an Internet Computer application. The pre-built canister is added to the project `dfx.json` and then configured to meet the needs of the application. `ic_siwe_provider` can be added to any Internet Computer application, independent of the application's programming language.

2. **Use the [ic_siwe](https://crates.io/crates/ic_siwe) library**: This allows developers full control over the SIWE integration. The `ic_siwe` Rust library provides all the necessary tools for integrating SIWE into IC canisters.

### SIWE login flow

The below diagram illustrates the high-level login flow when using the `ic_siwe_provider` canister.

1. An ICP application requests a SIWE message from the `ic_siwe_provider` canister on behalf of the user.

2. The application displays the SIWE message to the user who signs it with their Ethereum wallet.

3. The application sends the signed SIWE message to the `ic_siwe_provider` canister to login the user. The canister verifies the signature and creates an identity for the user.

4. The application retrieves the identity from the `ic_siwe_provider` canister.

5. The application can now use the identity to make authenticated calls to canisters.

![Sign in with Ethereum - Login flow](/media/flow.png)

## Resources

`ic-siwe` consists of two main packages: the Rust support library and the prebuilt identity provider canister. The project also includes React demo applications and React hooks for easy frontend integration with SIWE enabled Internet Computer canisters.

### [ic_siwe](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe)

Rust library that provides the necessary tools for integrating Sign-In with Ethereum (SIWE) into IC canisters, allowing users to sign in using their Ethereum wallets.

### [ic-siwe-provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider)

Prebuilt canister serving as a SIWE identity provider for Internet Computer canisters. `ic_siwe-provider` packages the [ic_siwe](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe) library and makes it available as a canister that can easily be integrated into any Internet Computer application, independent of the application's programming language.

### [ic-siwe-react-demo-rust](https://github.com/kristoferlund/ic-siwe-react-demo-rust)

React demo application that demonstrates how to integrate SIWE into an Internet Computer canister using the [ic-use-siwe-identity](https://github.com/kristoferlund/ic-use-siwe-identity) hook and [ic-siwe-provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider) canister.

Try the deployed demo here: https://shtr2-2iaaa-aaaal-qckva-cai.icp0.io

### [ic-siwe-react-demo-ts](https://github.com/kristoferlund/ic-siwe-react-demo-ts)

Same demo as above but this time the backend canister is written in TypeScript using [Azle](https://github.com/demergent-labs/azle).

Try the deployed demo here: https://zwsg3-myaaa-aaaal-qdf7q-cai.icp0.io/

### [ic-use-siwe-identity](https://github.com/kristoferlund/ic-use-siwe-identity)

React hook and context provider for easy frontend integration with SIWE enabled Internet Computer canisters.

### [ic-use-actor](https://github.com/kristoferlund/ic-use-actor)

React hook and context provider for managing Internet Computer (IC) actors with features like type safety and request/response interceptors. `ic-use-actor` makes interacting with Internet Computer canisters more fun!

## Updates

See the respective package CHANGELOG for details on updates.

## Contributing

Contributions are welcome. Please submit your pull requests or open issues to propose changes or report bugs.

## Author

- [kristofer@kristoferlund.se](mailto:kristofer@kristoferlund.se)
- Twitter: [@kristoferlund](https://twitter.com/kristoferlund)
- Discord: kristoferkristofer
- Telegram: [@kristoferkristofer](https://t.me/kristoferkristofer)

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Future Plans

The project is still in active development. Before using `ic-siwe` in production, I would like to do a more formal security audit.

Also, I want to integrate SIWE into more demo applications, ideally some wallet application.

Most likely, there are features missing in the current implementation. If you have any ideas or requests for features, please let me know by [opening an issue](https://github.com/kristoferlund/ic-siwe/issues).
