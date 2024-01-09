# ic-siwe

The `ic-siwe` library allows Ethereum developers to extend their applications onto the Internet Computer (IC) platform, allowing users to sign in with their Ethereum wallets to interact with IC canisters.

### Key Features:

- **Ethereum Wallet Sign-In**: Enables Ethereum wallet sign-in for IC applications. Sign in with any eth wallet to generate an IC identity and session.
- **Session Identity Uniqueness**: Ensures that session identities are specific to each application's context, preventing cross-app identity misuse.
- **Consistent Principal Generation**: Guarantees that logging in with an Ethereum wallet consistently produces the same Principal, irrespective of the client used.
- **Direct Ethereum Address to Principal Mapping**: Creates a one-to-one correlation between Ethereum addresses and Principals within the scope of the current application.
- **Timebound Sessions**: Allows developers to set expiration times for sessions, enhancing security and control.

The project's main goal is to enable secure and efficient session establishment between Ethereum applications and IC canisters, fostering the creation of innovative cross-chain applications by leveraging the combined strengths of the Ethereum and IC ecosystems.

### ⚠️ This is a work in progress ⚠️

Code is not production ready. Expect breaking changes. Code is not fully tested and audited. Once the code is stable, it will be published to crates.io.

## Demo

A React demo is available at: https://github.com/kristoferlund/ic-siwe-react-demo-rust.

Deployed demo can be accessed here: https://shtr2-2iaaa-aaaal-qckva-cai.icp0.io
