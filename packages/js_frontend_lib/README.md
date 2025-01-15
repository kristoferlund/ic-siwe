![Sign in with Ethereum for the Internet Computer](/media/header.png)

`ic-use-siwe-identity` is a React hook and context provider for easy frontend integration with SIWE enabled [Internet Computer](https://internetcomputer.org) canisters.

`ic-use-siwe-identity` is part of the [ic-siwe](https://github.com/kristoferlund/ic-siwe) project that enables Ethereum wallet-based authentication for applications on the Internet Computer (ICP) platform. The goal of the project is to enhance the interoperability between Ethereum and the Internet Computer platform, enabling developers to build applications that leverage the strengths of both platforms.

A SIWE enabled canister is a canister that integrates the [ic_siwe](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe) library and exposes the [SIWE login interface](src/siwe-identity-service.interface.ts). The `ic_siwe` library provides a set of functions for managing Internet Computer delegate identities created using Ethereum signatures.

[![version][version-image]][npm-link]
[![downloads][dl-image]][npm-link]

## Features

- **Cached Identity**: The identity is cached in local storage and restored on page load. This allows the user to stay logged in even if the page is refreshed.
- **Login progress**: State varibles are provided to indicate whether the user is logged in, logging in, or logged out.
- **Wagmi Integration**: Uses [wagmi](https://wagmi.sh) for Ethereum wallet integration.
- **Works with ic-use-actor**: Plays nicely with [ic-use-actor](https://www.npmjs.com/package/ic-use-actor) for hassle free frontend integration.
- **Works with ic_siwe_provider**: An easy alternative to integrating with `ic_siwe` directly is using the prebuilt [ic_siwe_provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider) canister. The provider canister can be added to your project as a dependency and used as a login provider for you project.

## Table of Contents

- [Features](#features)
- [Table of Contents](#table-of-contents)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Add an Ethereum wallet provider](#1-add-an-ethereum-wallet-provider)
  - [2. Setup the `SiweIdentityProvider` component](#2-setup-the-siweidentityprovider-component)
  - [3. Prepare the login](#3-prepare-the-login)
  - [4. Initiate the login process](#4-initiate-the-login-process)
- [SiweIdentityProvider props](#siweidentityprovider-props)
- [useSiweIdentity interface](#usesiweidentity-interface)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

## Installation

In addition to `ic-use-siwe-identity`, these peer dependencies are required:

- `wagmi`
- `viem`
- `@dfinity/agent`
- `@dfinity/candid`
- `@dfinity/identity`
- `@tanstack/query`

```bash
npm install ic-use-siwe-identity wagmi viem @dfinity/agent @dfinity/candid @dfinity/identity 
```

## Usage

> [!TIP]
> For a complete example, see the [ic-siwe-react-demo-rust](https://github.com/kristoferlund/ic-siwe-react-demo-rust) demo project.

To use `ic-use-siwe-identity` in your React application, follow these steps:

### 1. Add an Ethereum wallet provider

Before interacting with the useSiweIdentity hook, you need to add an Ethereum wallet provider to your application. The easiest way to do this is by using the [wagmi](https://wagmi.sh) library. Wagmi provides a React hook for connecting to Ethereum wallets, and is used internally by `ic-use-siwe-identity`. In addition to the wallet provider, wagmi requires you to add TanStack `QueryClientProvider` to your application that handles the async requests that are made when interacting with the Ethereum wallet.

We also recommend adding [RainbowKit](https://www.rainbowkit.com/) to handle the wallet connection UI.

```jsx
// main.tsx

const queryClient = new QueryClient();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <WagmiConfig config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider>
          // ...your app
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiConfig>
  </React.StrictMode>
);
```

> [!TIP]
> Check the [wagmi](https://wagmi.sh) and [RainbowKit](https://www.rainbowkit.com) documentation for the most up-to-date setup instructions.


### 2. Setup the `SiweIdentityProvider` component

Wrap your application's root component with `SiweIdentityProvider` to provide all child components access to the SIWE identity context. Provide the component with the `_SERVICE` type argument, where `_SERVICE` represents the canister service definition of a canister that implements the [SIWE login interface](src/service.interface.ts). This could be a canister that you have created yourself, using the [ic_siwe](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe) library, or the prebuilt [ic_siwe_provider](https://github.com/kristoferlund/ic-siwe/tree/main/packages/ic_siwe_provider) canister. Adding the provider canister to your project as a dependency is the easiest way to get started.

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
      // ...your app components
    </App>
  );
}
```

### 3. Prepare the login

This is an optional step, as the login process will automatically call `prepareLogin` if it has not been called manually. However, calling `prepareLogin` before initiating the login process improves the user experience by reducing the time it takes to complete the login process. The `prepareLogin` function requests a SIWE message from the backend. This is an update call that usually takes two to three seconds to complete.

The `prepareLoginStatus` state variable can be used to indicate the status of the prepare login process. Errors that occur during the prepare login process are stored in the `prepareLoginError` state variable.

> [!IMPORTANT]
> Be sure to call `prepareLogin` again on wallet change, as the SIWE message is unique to the Ethereum address of the user. If the user changes their wallet, the SIWE message will be invalid and a new one must be requested.

```jsx
const { isConnected, address } = useAccount(); // Wagmi hook
const { prepareLogin, prepareLoginStatus, prepareLoginError, loginError } =
  useSiweIdentity();

/**
 * Preload a Siwe message on every address change.
 */
useEffect(() => {
  if (prepareLoginStatus !== "idle" || !isConnected || !address) return;
  prepareLogin();
}, [isConnected, address, prepareLogin, prepareLoginStatus]);
```

### 4. Initiate the login process

The login process is initiated by calling the `login` function. This function requests a SIWE message from the backend if it has not already been loaded. The user is asked to sign the message using their Ethereum wallet and the signed message is sent to the backend for authentication. Once the authentication is complete, the user's identity is stored in local storage and the `identity` state variable is updated with the new identity.

The `loginStatus` state variable can be used to indicate the status of the login process. Errors that occur during the login process are stored in the `loginError` state variable.

```jsx
const { isConnected } = useAccount(); // Wagmi hook
const { login, loginStatus, prepareLoginStatus } = useSiweIdentity();

const text = loginStatus === "logging-in" ? "Signing in …" : "Sign in";

const disabled =
  loginStatus === "logging-in" ||
  !isConnected ||
  prepareLoginStatus !== "success";

return (
  <Button disabled={disabled} onClick={login}>
    {text}
  </Button>
);
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
  /** Is set to `true` on mount until a stored identity is loaded from local storage or
   * none is found. */
  isInitializing: boolean;

  /** Load a SIWE message from the provider canister, to be used for login. Calling prepareLogin
   * is optional, as it will be called automatically on login if not called manually. */
  prepareLogin: () => void;

  /** "error" | "loading" | "success" | "idle" - Reflects the current status of the prepareLogin process. */
  prepareLoginStatus: PrepareLoginStatus;

  /** Error that occurred during the prepareLogin process. */
  prepareLoginError?: Error;

  /** Initiates the login process by requesting a SIWE message from the backend. */
  login: () => Promise<DelegationIdentity | undefined>;

  /** "error" | "success" | "idle" | "logging-in" - Reflects the current status of the login process. */
  loginStatus: LoginStatus;

  /** Error that occurred during the login process. */
  loginError?: Error;

  /** Status of the SIWE message signing process. This is a re-export of the Wagmi
   * signMessage / status type. */
  signMessageStatus: "error" | "idle" | "pending" | "success"

  /** Error that occurred during the SIWE message signing process. This is a re-export of the
   * Wagmi signMessage / error type. */
  signMessageError: Error | null;

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

  /** Clears the identity from the state and local storage. Effectively "logs the user out". */
  clear: () => void;
};
```

## Contributing

Contributions are welcome. Please submit your pull requests or open issues to propose changes or report bugs.

## Author

- [kristofer@fmckl.se](mailto:kristofer@fmckl.se)
- Twitter: [@kristoferlund](https://twitter.com/kristoferlund)
- Discord: kristoferkristofer
- Telegram: [@kristoferkristofer](https://t.me/kristoferkristofer)

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

[version-image]: https://img.shields.io/npm/v/ic-use-siwe-identity
[dl-image]: https://img.shields.io/npm/dw/ic-use-siwe-identity
[npm-link]: https://www.npmjs.com/package/ic-use-siwe-identity
