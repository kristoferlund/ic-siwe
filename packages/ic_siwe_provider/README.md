![Sign in with Ethereum for the Internet Computer](/media/header.png)

Using the pre built `ic_siwe_provider` canister is the easiest way to integrate Ethereum wallet authentication into your [Internet Computer](https://internetcomputer.org) application.

The canister is designed as a plug-and-play solution for developers, enabling easy integration into existing IC applications with minimal coding requirements. By adding the pre built `ic_siwe_provider` canister to the `dfx.json` of an IC project, developers can quickly enable Ethereum wallet-based authentication for their applications. The canister simplifies the authentication flow by managing the creation and verification of SIWE messages and handling user session management.

`ic_siwe_provider` is part of the [ic-siwe](https://github.com/kristoferlund/ic-siwe) project that enables Ethereum wallet-based authentication for applications on the Internet Computer (IC) platform. The goal of the project is to enhance the interoperability between Ethereum and the Internet Computer platform, enabling developers to build applications that leverage the strengths of both platforms.

## Features

- **Prebuilt**: The canister is pre built and ready to use.
- **Configurable**: The `ic_siwe_provider` canister allows developers to customize the SIWE authentication flow to suit their needs.
- **Easy Integration**: The canister can be easily integrated into any Internet Computer application, independent of the application's programming language.
- **Keeps Ethereum Wallets Private**: The canister never has access to the user's Ethereum wallet, ensuring that the user's private keys are never exposed.
- **Session Identity Uniqueness**: Ensures that session identities are specific to each application's context, preventing cross-app identity misuse.
- **Consistent Principal Generation**: Guarantees that logging in with an Ethereum wallet consistently produces the same Principal, irrespective of the client used.
- **Direct Ethereum Address to Principal Mapping**: Creates a one-to-one correlation between Ethereum addresses and Principals within the scope of the current application.
- **Timebound Sessions**: Allows developers to set expiration times for sessions, enhancing security and control.

## Integration overview

See the [ic-siwe-react-demo-rust](https://github.com/kristoferlund/ic-siwe-react-demo-rust) for a complete example of how to integrate the `ic_siwe_provider` canister into an IC application. The easiest way to get started is to fork the demo and modify it to suit your needs.

The high-level integration flow for the `ic_siwe_provider` canister is as follows:

1. An IC application requests a SIWE message from the `ic_siwe_provider` canister on behalf of the user.
2. The application displays the SIWE message to the user who signs it with their Ethereum wallet.
3. The application sends the signed SIWE message to the `ic_siwe_provider` canister to login the user. The canister verifies the signature and creates an identity for the user.
4. The application retrieves the identity from the `ic_siwe_provider` canister.
5. The application can now use the identity to make authenticated calls to canisters.

![Sign in with Ethereum - Login flow](/media/flow.png)

## Installation

### 1. Add the `ic_siwe_provider` canister to your `dfx.json`

The canister is pre built and ready to use. To add it to your project, simply add it to the `dfx.json` file in the `canisters` section:

```json
{
  "canisters": {
    "ic_siwe_provider": {
      "type": "custom",
      "candid": "https://github.com/kristoferlund/ic_siwe/raw/64bd789446838bebb6cad49c5bc3b556da4acd02/packages/ic_siwe_provider/ic_siwe_provider.did",
      "wasm": "https://github.com/kristoferlund/ic_siwe/raw/64bd789446838bebb6cad49c5bc3b556da4acd02/packages/ic_siwe_provider/ic_siwe_provider.wasm.gz"
    },
    ...
  },
  ...
}
```

### 2. Configure the `ic_siwe_provider` on deploy

The `ic_siwe_provider` canister needs to be configured on deploy. The configuration is passed as an argument to the canister `init` function. Below is an example of how to configure the canister using the `dfx` command line tool:

```bash
dfx deploy ic_siwe_provider --argument $'(
    record {
        domain = "127.0.0.1";
        uri = "http://127.0.0.1:5173";
        salt = "my secret salt";
        chain_id = opt 1;
        scheme = opt "http";
        statement = opt "Login to the app";
        sign_in_expires_in = opt 300000000000;       # 5 minutes
        session_expires_in = opt 604800000000000;    # 1 week
        targets = opt vec {
            "'$(dfx canister id ic_siwe_provider)'"; # Must be included
            "'$(dfx canister id my_app_canister)'";  # Allow identity to be used with this canister
        };
    }
)'
```

### 3. Integrate the `ic_siwe_provider` into your frontend application

Below example uses the [ic-use-siwe-identity](https://github.com/kristoferlund/ic_siwe/tree/main/packages/ic-use-siwe-identity) React hook to integrate the `ic_siwe_provider` into a React application.

Wrap your application's root component with `SiweIdentityProvider` to provide all child components access to the SIWE identity context.

```jsx
// App.tsx

import { SiweIdentityProvider } from 'ic-use-siwe-identity';
import { _SERVICE } from "path-to/ic_siwe_provider.did";

function App() {
  return (
    <SiweIdentityProvider<_SERVICE>
      idlFactory={/* IDL Interface Factory */}
      canisterId={/* Canister ID */}
      // ...other props
    >
      {/* Your app components */}
    </App>
  );
}
```

### 4. Use the `useSiweIdentity` hook

Use the useSiweIdentity hook to initiate the login process:

```jsx
// Component.tsx

import { useSiweIdentity } from "ic-use-siwe-identity";

function MyComponent() {
  const { login, clear, identity, ... } = useSiweIdentity();
  // ...
}
```

## API

The `ic_siwe_provider` canister exposes the following endpoints:

## API Endpoints

The `ic_siwe_provider` canister exposes several endpoints, each serving a specific function in the Ethereum wallet authentication process for Internet Computer applications.

### `get_address`

- **Purpose**: Retrieves the Ethereum address associated with a given IC principal.
- **Input**: A `ByteBuf` containing the principal's bytes (expected to be 29 bytes).
- **Output**:
  - `Ok(String)`: The EIP-55-compliant Ethereum address, if found.
  - `Err(String)`: An error message if the principal cannot be converted or no address is found.

### `get_caller_address`

- **Purpose**: Retrieves the Ethereum address associated with the caller. This is a convenience function that internally calls `get_address`.
- **Output**: Same as `get_address`.

### `get_delegation`

- **Purpose**: Fetches the delegation to be used for authentication once the user is logged in.
- **Input**: Ethereum address (`String`), session key (`ByteBuf`), and expiration timestamp (`u64`).
- **Output**:
  - `Ok(SignedDelegation)`: The delegation if the process is successful.
  - `Err(String)`: An error message if there is a failure in fetching the delegation.

### `get_principal`

- **Purpose**: Retrieves the principal associated with the given Ethereum address.
- **Input**: The EIP-55-compliant Ethereum address (`String`).
- **Output**:
  - `Ok(ByteBuf)`: The principal if found.
  - `Err(String)`: An error message if the address cannot be converted or no principal is found.

### `login`

- **Purpose**: Verifies the signature of the SIWE message and prepares the delegation for authentication.
- **Input**: Signature (`String`), Ethereum address (`String`), and session key (`ByteBuf`).
- **Output**:
  - `Ok(LoginOkResponse)`: The public key and other login response data if the login is successful.
  - `Err(String)`: An error message if the login process fails.

### `prepare_login`

- **Purpose**: Generates a SIWE message challenge and returns it to the caller, initiating the login process.
- **Input**: Ethereum address (`String`).
- **Output**:
  - `Ok(String)`: The SIWE message challenge.
  - `Err(String)`: An error message if there is an error in preparing the login.

In addition to the key functionalities for Ethereum wallet authentication, the `ic_siwe_provider` canister includes initialization and upgrade endpoints essential for setting up and maintaining the canister.

### `init`

- **Purpose**: Initializes the `ic_siwe_provider` canister with necessary settings for the SIWE process.
- **Input**: `SettingsInput` struct containing configuration details like domain, URI, salt, chain ID, etc.
- **Operation**: Sets up the SIWE library with the provided settings. This function is invoked when the canister is created.

### `upgrade`

- **Purpose**: Maintains the state and settings of the `ic_siwe_provider` canister during an upgrade.
- **Input**: `SettingsInput` struct similar to the `init` function.
- **Operation**: Ensures that the SIWE settings and state are preserved and reapplied after the canister is upgraded.

## Data Structures

The `ic_siwe_provider` canister uses several data structures to facilitate the Ethereum wallet authentication process. These data structures are defined in the `ic_siwe` library and are used by the `ic_siwe_provider` canister.

### SettingsInput

```rust
pub struct SettingsInput {
    // The domain from where the frontend that uses SIWE is served.
    pub domain: String,

    // The full URI, potentially including port number of the frontend that uses SIWE.
    pub uri: String,

    // The salt is used when generating the seed that uniquely identifies each user principal.
    pub salt: String,

    // Optional. The Ethereum chain ID for ic_siwe, defaults to 1 (Ethereum mainnet).
    pub chain_id: Option<u32>,

    // Optional. The scheme used to serve the frontend that uses SIWE. Defaults to "https".
    pub scheme: Option<String>,

    // Optional. The statement is a message or declaration, often presented to the user by the Ethereum wallet
    pub statement: Option<String>,

    // Optional. The TTL for a sign-in message in nanoseconds. After this time, the sign-in message will be pruned.
    pub sign_in_expires_in: Option<u64>,

    // Optional. The TTL for a session in nanoseconds.
    pub session_expires_in: Option<u64>,

    // Optional. The list of canisters for which the identity delegation is allowed. Defaults to None, which means
    // that the delegation is allowed for all canisters.
    pub targets: Option<Vec<String>>,
}
```

## Updates

See the [CHANGELOG](CHANGELOG.md) for details on updates.

## Contributing

Contributions are welcome. Please submit your pull requests or open issues to propose changes or report bugs.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
