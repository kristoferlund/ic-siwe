![Sign in with Ethereum for the Internet Computer](/media/header.png)

Using the pre built `ic_siwe_provider` canister is the easiest way to integrate Ethereum wallet authentication into an [Internet Computer](https://internetcomputer.org) (ICP) application.

The canister is designed as a plug-and-play solution for developers, enabling easy integration into existing ICP applications with minimal coding requirements. By adding the pre built `ic_siwe_provider` canister to the `dfx.json` of an ICP project, developers can quickly enable Ethereum wallet-based authentication for their applications. The canister simplifies the authentication flow by managing the creation and verification of SIWE messages and handling user session management.

`ic_siwe_provider` is part of the [ic-siwe](https://github.com/kristoferlund/ic-siwe) project that enables Ethereum wallet-based authentication for applications on the Internet Computer (ICP) platform. The goal of the project is to enhance the interoperability between Ethereum and the Internet Computer platform, enabling developers to build applications that leverage the strengths of both platforms.

## Features

- **Prebuilt**: The canister is pre built and ready to use.
- **Configurable**: The `ic_siwe_provider` canister allows developers to customize the SIWE authentication flow to suit their needs.
- **Easy Integration**: The canister can be easily integrated into any Internet Computer application, independent of the application's programming language.
- **Keeps Ethereum Wallets Private**: The canister never has access to the user's Ethereum wallet, ensuring that the user's private keys are never exposed.
- **Session Identity Uniqueness**: Ensures that session identities are specific to each application's context, preventing cross-app identity misuse.
- **Consistent Principal Generation**: Guarantees that logging in with an Ethereum wallet consistently produces the same Principal, irrespective of the client used.
- **Direct Ethereum Address to Principal Mapping**: Creates a one-to-one correlation between Ethereum addresses and Principals within the scope of the current application.
- **Timebound Sessions**: Allows developers to set expiration times for sessions, enhancing security and control.

## Table of Contents

- [Integration overview](#integration-overview)
- [Installation](#installation)
- [Runtime Features](#runtime-features)
- [Service Interface](#service-interface)
- [Data Structures](#data-structures)
- [Updates](#updates)
- [Contributing](#contributing)
- [License](#license)

## Integration overview

See the [ic-siwe-react-demo-rust](https://github.com/kristoferlund/ic-siwe-react-demo-rust) for a complete example of how to integrate the `ic_siwe_provider` canister into an ICP application. The easiest way to get started is to fork the demo and modify it to suit your needs.

The [integration tests](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/tests/integration_tests.rs) for the `ic_siwe_provider` canister also provide a good overview of how to integrate the canister into an ICP application.

The high-level integration flow for the `ic_siwe_provider` canister is as follows:

1. An ICP application requests a SIWE message from the `ic_siwe_provider` canister on behalf of the user.
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
      "candid": "https://github.com/kristoferlund/ic-siwe/releases/download/v0.1.1/ic_siwe_provider.did",
      "wasm": "https://github.com/kristoferlund/ic-siwe/releases/download/v0.1.1/ic_siwe_provider.wasm.gz"
    }
  }
}
```

### 2. Configure the `ic_siwe_provider` on deploy

The `ic_siwe_provider` canister needs to be configured on deploy. The configuration is passed as an argument to the canister `init` function. Below is an example of how to configure the canister using the `dfx` command line tool:

```bash
dfx deploy ic_siwe_provider --argument $'(
    record {
        domain = "127.0.0.1";
        uri = "http://127.0.0.1:5173";
        salt = "mysecretsalt123";
        chain_id = opt 1;
        scheme = opt "http";
        statement = opt "Login to the app";
        sign_in_expires_in = opt 300000000000;
        session_expires_in = opt 604800000000000;
        targets = opt vec {
            "'$(dfx canister id ic_siwe_provider)'";
            "'$(dfx canister id my_app_canister)'";
        };
    }
)'
```

> [!IMPORTANT]
> `domain` should be set to the full domain, including subdomains, from where the frontend that uses SIWS is served.
> Example: `myapp.example.com`
>
> `uri` should be set to the full URI, potentially including the port number, of the frontend that uses SIWS.
> Example: `https://myapp.example.com:8080`

See also additional [runtime features](#runtime-features) that can be configured.

### 3. Integrate the `ic_siwe_provider` into your frontend application

Below example uses the [ic-siwe-js](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_js) React hook to integrate the `ic_siwe_provider` into a React application.

Wrap your application's root component with `SiweIdentityProvider` to provide all child components access to the SIWE identity context.

```jsx
// App.tsx

import { SiweIdentityProvider } from 'ic-siwe-js/react';
import { canisterId } from "../../ic_siwe_provider/declarations/index";

function App() {
  return (
    <SiweIdentityProvider
      canisterId={/* Canister ID */}
      // ...other props
    >
      {/* Your app components */}
    </App>
  );
}
```

### 4. Use the `useSiwe` hook

Use the `useSiwe` hook to initiate the login process:

```jsx
// Component.tsx

import { useSiwe } from "ic-siwe-js/react";

function MyComponent() {
  const { login, clear, identity, ... } = useSiweIdentity();
  // ...
}
```

## Runtime Features

The runtime behaviour of the `ic_siwe_provider` canister and the `ic_siwe` library can be customized using the following settings:

### `IncludeUriInSeed`

Default: URI is not included in the seed

When set, the URI is included in the seed used to generate the principal. Including the URI in the seed does not add any additional security in a scenario where `ic_siwe_provider` is deployed and configured to serve only one domain. However, if the `ic_siwe` library is used in a custom canister, that delagetes identities for more than one domain, it is recommended to enable this feature to ensure that the principal is unique for each domain.

```bash
  runtime_features = opt vec { \
    variant { IncludeUriInSeed } \
  };
```

### `DisableEthToPrincipalMapping`

Default: Mapping is enabled

When set, the mapping of Ethereum addresses to Principals is disabled. This also disables the canister endpoints `get_principal`.

```bash
  runtime_features = opt vec { \
    variant { DisableEthToPrincipalMapping } \
  };
```

### `DisablePrincipalToEthMapping`

Default: Mapping is enabled

When set, the mapping of Principals to Ethereum addresses is disabled. This also disables the canister endpoints `get_address` and `get_caller_address`.

```bash
  runtime_features = opt vec { \
    variant { DisablePrincipalToEthMapping } \
  };
```

## Service Interface

In addition to the SIWE endpoints, required by the `useSiweIdentity` hook, this canister also exposes endpoints to retrieve the Ethereum address associated with a given ICP principal and vice versa. These endpoints are useful for applications that need to map ICP Principals to Ethereum addresses.

### [get_address](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/src/service/get_address.rs)

- **Purpose**: Retrieves the Ethereum address associated with a given ICP principal.
- **Input**: A `ByteBuf` containing the principal's bytes (expected to be 29 bytes).
- **Output**:
  - `Ok(String)`: The EIP-55-compliant Ethereum address, if found.
  - `Err(String)`: An error message if the principal cannot be converted or no address is found.

### [get_caller_address](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/src/service/get_calle_address.rs)

- **Purpose**: Retrieves the Ethereum address associated with the caller. This is a convenience function that internally calls `get_address`.
- **Output**: Same as `get_address`.

### [get_principal](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/src/service/get_principal.rs)

- **Purpose**: Retrieves the principal associated with the given Ethereum address.
- **Input**: The EIP-55-compliant Ethereum address (`String`).
- **Output**:
  - `Ok(ByteBuf)`: The principal if found.
  - `Err(String)`: An error message if the address cannot be converted or no principal is found.

### [siwe_prepare_login](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/src/service/siwe_prepare_login.rs)

- **Purpose**: Generates a SIWE message challenge and returns it to the caller, initiating the login process.
- **Input**: Ethereum address (`String`).
- **Output**:
  - `Ok(PrepareLoginOkResponse)`: The prepared SIWE message and nonce.
  - `Err(String)`: An error message if there is an error in preparing the login.

### [siwe_login](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/src/service/siwe_login.rs)

- **Purpose**: Verifies the signature of the SIWE message and prepares the delegation for authentication.
- **Input**: Signature (`String`), Ethereum address (`String`), session key (`ByteBuf`), and nonce (`String`).
- **Output**:
  - `Ok(LoginDetails)`: The public key and other login response data if the login is successful.
  - `Err(String)`: An error message if the login process fails.

### [siwe_get_delegation](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/src/service/siwe_get_delegation.rs)

- **Purpose**: Fetches the delegation to be used for authentication once the user is logged in.
- **Input**: Ethereum address (`String`), session key (`ByteBuf`), and expiration timestamp (`u64`).
- **Output**:
  - `Ok(SignedDelegation)`: The delegation if the process is successful.
  - `Err(String)`: An error message if there is a failure in fetching the delegation.

In addition to the key functionalities for Ethereum wallet authentication, the `ic_siwe_provider` canister includes initialization and upgrade endpoints essential for setting up and maintaining the canister.

### [init](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/src/service/init.rs)

- **Purpose**: Initializes the `ic_siwe_provider` canister with necessary settings for the SIWE process.
- **Input**: `SettingsInput` struct containing configuration details like domain, URI, salt, chain ID, etc.
- **Operation**: Sets up the SIWE library with the provided settings. This function is invoked when the canister is created.

### [upgrade](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/src/service/upgrade.rs)

- **Purpose**: Maintains the state and settings of the `ic_siwe_provider` canister during an upgrade.
- **Input**: `SettingsInput` struct similar to the `init` function.
- **Operation**: Ensures that the SIWE settings and state are preserved and reapplied after the canister is upgraded.

## Data Structures

### RuntimeFeature

```rust
pub enum RuntimeFeature {
    // Enabling this feature will include the app frontend URI as part of the identity seed.
    IncludeUriInSeed,

    // Disable the mapping of Ethereum address to principal. This also disables canister endpoints `get_principal`.
    DisableEthToPrincipalMapping,

    // Disable the mapping of principal to Ethereum address. This also disables canister endpoints `get_address` and `get_caller_address`.
    DisablePrincipalToEthMapping,
}
```

### SettingsInput

Defines the settings that controls the behavior of the `ic_siwe_provider` canister.

```rust
pub struct SettingsInput {
    // The full domain, including subdomains, from where the frontend that uses SIWE is served.
    // Example: "example.com" or "sub.example.com".
    pub domain: String,

    // The full URI, potentially including port number of the frontend that uses SIWE.
    // Example: "https://example.com" or "https://sub.example.com:8080".
    pub uri: String,

    // The salt is used when generating the seed that uniquely identifies each user principal. The salt can only contain
    /// printable ASCII characters.
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

    // Optional. The runtime features that control the behavior of the SIWE library.
    pub runtime_features: Option<Vec<RuntimeFeature>>,
}
```

## Updates

## Contributing

Contributions are welcome. Please submit your pull requests or open issues to propose changes or report bugs.

## Author

- [kristofer@fmckl.se](mailto:kristofer@fmckl.se)
- Twitter: [@kristoferlund](https://twitter.com/kristoferlund)
- Discord: kristoferkristofer
- Telegram: [@kristoferkristofer](https://t.me/kristoferkristofer)

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
