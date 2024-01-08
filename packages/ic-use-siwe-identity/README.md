# ic-use-siwe-identity

React hook and context provider for easy frontend integration with SIWE enabled Internet Computer canisters.

**TL;DR:** `ic_siwe` allows users to login to Internet Computer canisters using their Ethereum wallet.

A SIWE enabled canister is a canister that integrates the `ic_siwe` library and exposes the [SIWE login interface](src/siwe-identity-service.interface.ts). The `ic_siwe` library provides a set of functions for managing Internet Computer delegate identities created using Ethereum signatures. The library is available here: [ic-siwe](https://github.com/kristoferlund/ic-siwe).

![npm](https://img.shields.io/npm/v/ic-use-siwe-identity)
![npm](https://img.shields.io/npm/dw/ic-use-siwe-identity)

## Features

- **Cached Identity**: The identity is cached in local storage and restored on page load. This allows the user to stay logged in even if the page is refreshed.
- **Login progress**: State varibles are provided to indicate whether the user is logged in, logging in, or logged out.
- **Wagmi Integration**: Uses [wagmi](https://wagmi.sh) for Ethereum wallet integration.
- **Works with ic-use-actor**: Plays nicely with [ic-use-actor](https://www.npmjs.com/package/ic-use-actor) for hassle free frontend integration.
- **Works with ic_siwe_provider**: An easy alternative to integrating with `ic_siwe` directly is using the prebuilt [ic_siwe_provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider) canister. The provider canister can be added to your project as a dependency and used as a proxy for all `ic_siwe` calls.

## Login Flow

### 1. **Initialization**

On mount, the `SiweIdentityProvider` component initializes by creating an anonymous actor and loading any existing identity from local storage.

### 2. **Starting the Login Process**

The login process begins with the `login` function. It requests a SIWE message from the backend, which the user signs using their Ethereum wallet.

### 3. **Processing the Signed Message**

Once the user signs the SIWE message, the library handles the authentication with the backend. It involves generating a session identity and establishing a delegation chain.

### 4. **Completing the Authentication**

After successful backend authentication, the user's session identity and delegation chain are stored both locally and in the component's state, finalizing the login process.

## Installation

In addition to `ic-use-siwe-identity`, the following packages are required:

- `@dfinity/agent`
- `@dfinity/identity`
- `@dfinity/candid`
- `wagmi`
- `viem`

```bash
npm install ic-use-siwe-identity @dfinity/agent @dfinity/identity @dfinity/candid wagmi viem
```

## Usage

To use `ic-use-siwe-identity` in your React application, follow these steps:

### 1. Setup the `SiweIdentityProvider` component

Wrap your application's root component with `SiweIdentityProvider` to provide all child components access to the SIWE identity context. Provide the component with the `_SERVICE`
type argument, where `_SERVICE` represents the canister service definition of a canister that implements the [SIWE login interface](src/siwe-identity-service.interface.ts).

```jsx
// App.tsx

import { SiweIdentityProvider } from 'ic-use-siwe-identity';
import { _SERVICE } from "path-to/siwe-enabled-canister.did";

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

### 2. Use the `useSiweIdentity` hook

Use the useSiweIdentity hook in your components to access identity-related functionalities:

```jsx
// Component.tsx

import { useSiweIdentity } from "ic-use-siwe-identity";

function MyComponent() {
  const { login, clear, identity, ... } = useSiweIdentity();
  // ...
}
```

## SiweIdentityProvider props

```ts
{
  /** Configuration options for the HTTP agent used to communicate with the Internet Computer network. */
  httpAgentOptions?: HttpAgentOptions;

  /** Configuration options for the actor. These options are passed to the actor upon its creation. */
  actorOptions?: ActorConfig;

  /** The Interface Description Language (IDL) factory for the canister. This factory is used to create an actor interface for the canister. */
  idlFactory: IDL.InterfaceFactory;

  /** The unique identifier of the canister on the Internet Computer network. This ID is used to establish a connection to the canister. */
  canisterId: string;

  /** The child components that the SiweIdentityProvider will wrap. This allows any child component to access the authentication context provided by the SiweIdentityProvider. */
  children: ReactNode;
}
```

## useSiweIdentity interface

```ts
export type SiweIdentityContextType = {
  /** Initiates the login process by requesting a SIWE message from the backend. */
  login: () => void;

  /** Clears the identity from the state and local storage. Effectively "logs the user out". */
  clear: () => void;

  /** Is set to `true` on mount until the identity is loaded from local storage. */
  isLoading: boolean;

  /** Is set to `true` while the login process is in progress. */
  isLoggingIn: boolean;

  /** Status of the SIWE message signing process. This is a re-export of the Wagmi
   * signMessage / status type. */
  signMessageStatus: "idle" | "pending" | "success" | "error";

  /** The delegation chain is available after successfully loading the identity from local
   * storage or completing the login process. */
  delegationChain?: DelegationChain;

  /** The identity is available after successfully loading the identity from local storage
   * or completing the login process. */
  identity?: DelegationIdentity;

  /** The Ethereum address associated with current identity. This address is not necessarily
   * the same as the address of the currently connected wallet - on wallet change, the addresses
   * will differ. */
  identityAddress?: string;
};
```

## Contributing

Contributions are welcome. Please submit your pull requests or open issues to propose changes or report bugs.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
