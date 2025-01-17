![Sign in with Ethereum for the Internet Computer](/media/header.png)

`ic-siwe-js` is a JS/TS support library for easy frontend integration with SIWE enabled [Internet Computer](https://internetcomputer.org) canisters. In addition to the plain JS/TS library, `ic-siwe-js` provides a **React hook and context provider**.

This library is part of the [ic-siwe](https://github.com/kristoferlund/ic-siwe) project that enables Ethereum wallet-based authentication for applications on the Internet Computer (ICP) platform. The goal of the project is to enhance the interoperability between Ethereum and the Internet Computer platform, enabling developers to build applications that leverage the strengths of both platforms.

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

- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage with React](#usage-with-react)
  - [1. Add an Ethereum library for React](#1-add-an-ethereum-library-for-react)
  - [2. Setup the `SiweIdentityProvider` component](#2-setup-the-siweidentityprovider-component)
  - [3. Initiate the login process](#3-initiate-the-login-process)
- [SiweIdentityProvider props](#siweidentityprovider-props)
- [useSiwe interface](#usesiwe-interface)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

## Installation

In addition to `ic-siwe-js`, these peer dependencies are required:

- `viem`
- `@dfinity/agent`
- `@dfinity/candid`
- `@dfinity/identity`

```bash
npm install ic-siwe-js viem @dfinity/agent @dfinity/candid @dfinity/identity 
```

## Quick start

> [!TIP]
> For a complete example, see the [ic-siwe-vanilla-ts-demo](https://github.com/kristoferlund/ic-siwe-vanilla-ts-demo) demo project.

```ts
import { canisterId } from "../../ic_siwe_provider/declarations/index";
import { SiweManager, siweStateStore } from "ic-siwe-js";

// Initialize the SiweManager with the canisterId of the SIWE provider canister.
const siwe = new SiweManager(canisterId);

// Set up HTML elements for login and logout buttons, etc.
// ...

// Interact with the SiweManager instance to trigger the login process or to logout.
loginButton.addEventListener("click", () => siwe.login());
logoutButton.addEventListener("click", () => siwe.clear());

// Listen for changes to the siweStateStore and update the UI accordingly.
siweStateStore.subscribe((snapshot) => {
  const {
    prepareLoginStatus,
    prepareLoginError,
    loginStatus,
    loginError,
    signMessageStatus,
  } = snapshot.context;

  if (loginStatus === "idle") {
    loginButton.innerHTML = "Login";
    loginButton.disabled = false;
  }
  if (loginStatus === "logging-in") {
    loginButton.innerHTML = "Logging in...";
    loginButton.disabled = true;
  }

  // Handle other states ...
}
```

## Usage with React

> [!TIP]
> For a complete example, see the [ic-siwe-react-demo-rust](https://github.com/kristoferlund/ic-siwe-react-demo-rust) demo project.

The React submodule comes with `SiweIdentityProvider` that makes the `SiweManager` available to all components in the app. It also provides a `useSiwe` hook that can be used to interact with the `SiweManager` instance.

### 1. Setup the `SiweIdentityProvider` component

Wrap your application's root component with `SiweIdentityProvider` to provide all child components access to the SIWE identity context. Provide the component with the canister id of the SIWE provider canister.

```jsx
// App.tsx

import { SiweIdentityProvider } from 'ic-siwe-js/react';
import { canisterId } from "../../ic_siwe_provider/declarations/index";

function App() {
  return (
    <SiweIdentityProvider canisterId={canisterId}>
      // ...your app components
    </App>
  );
}
```

### 2. Initiate the login process

The login process is initiated by calling the `login` function. This function requests a SIWE message from the backend if it has not already been loaded. The user is asked to sign the message using their Ethereum wallet and the signed message is sent to the backend for authentication. Once the authentication is complete, the user's identity is stored in local storage and the `identity` state variable is updated with the new identity.

The `loginStatus` state variable can be used to indicate the status of the login process. Errors that occur during the login process are stored in the `loginError` state variable.

```jsx
const { isConnected } = useAccount(); // Wagmi hook
const { login, loginStatus, prepareLoginStatus } = useSiwe();

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

## Usage with Vue

> [!TIP]
> For a complete example, see the [ic-siwe-vue-demo](https://github.com/kristoferlund/ic-siwe-vue-demo) demo project.

The Vue submodule comes with `SiweIdentityProvider` that makes the `SiweManager` available to all components in the app. It also provides a `useSiwe` hook that can be used to interact with the `SiweManager` instance.

### 1. Setup the `SiweIdentityProvider` component

In the `App.vue` component, initiate the `SiweIdentityProvider` with a reference to the SIWE provider canister to make it available to all child components.

```html
<script setup lang="ts">

import { createSiweIdentityProvider } from "ic-siwe-js/vue";
import { canisterId } from "../../ic_siwe_provider/declarations/index";

createSiweIdentityProvider({
  canisterId,
});

</script>

<template>
    <!-- Your app components -->
</template>
```

### 2. Initiate the login process

The login process is initiated by calling the `login` function. This function requests a SIWE message from the backend if it has not already been loaded. The user is asked to sign the message using their Ethereum wallet and the signed message is sent to the backend for authentication. Once the authentication is complete, the user's identity is stored in local storage and the `identity` state variable is updated with the new identity.

The `loginStatus` state variable can be used to indicate the status of the login process. Errors that occur during the login process are stored in the `loginError` state variable.

```html

<script setup lang="ts">
import { useSiwe } from "ic-siwe-js/vue";

const siwe = useSiwe();

</script>

<template>
  <div>
    <button @click="siwe.login">
      Login
    </button>

    <button @click="siwe.clear">
      Logout
    </button>
  </div>
</template>
```

## SiweIdentityProvider props

```ts
{
  /** The unique identifier of the canister on the Internet Computer network. This ID is used to establish a connection to the canister. */
  canisterId: string;

  /** Configuration options for the HTTP agent used to communicate with the Internet Computer network. */
  httpAgentOptions?: HttpAgentOptions;

  /** Configuration options for the actor. These options are passed to the actor upon its creation. */
  actorOptions?: ActorConfig;

  /** The child components that the SiweIdentityProvider will wrap. This allows any child component to access the authentication context provided by the SiweIdentityProvider. */
  children: ReactNode;
}
```

## useSiwe interface

```ts
export type PrepareLoginStatus = "error" | "preparing" | "success" | "idle";
export type LoginStatus = "error" | "logging-in" | "success" | "idle";
export type SignMessageStatus = "error" | "idle" | "pending" | "success";

export type SiweIdentityContextType = {
  /** Is set to `true` on mount until a stored identity is loaded from local storage or
   * none is found. */
  isInitializing: boolean;

  /** Load a SIWE message from the provider canister, to be used for login. Calling prepareLogin
   * is optional, as it will be called automatically on login if not called manually. */
  prepareLogin: () => void;

  /** Reflects the current status of the prepareLogin process. */
  prepareLoginStatus: PrepareLoginStatus;

  /** `prepareLoginStatus === "loading"` */
  isPreparingLogin: boolean;

  /** `prepareLoginStatus === "error"` */
  isPrepareLoginError: boolean;

  /** `prepareLoginStatus === "success"` */
  isPrepareLoginSuccess: boolean;

  /** `prepareLoginStatus === "idle"` */
  isPrepareLoginIdle: boolean;

  /** Error that occurred during the prepareLogin process. */
  prepareLoginError?: Error;

  /** Initiates the login process by requesting a SIWE message from the backend. */
  login: () => Promise<DelegationIdentity | undefined>;

  /** Reflects the current status of the login process. */
  loginStatus: LoginStatus;

  /** `loginStatus === "logging-in"` */
  isLoggingIn: boolean;

  /** `loginStatus === "error"` */
  isLoginError: boolean;

  /** `loginStatus === "success"` */
  isLoginSuccess: boolean;

  /** `loginStatus === "idle"` */
  isLoginIdle: boolean;

  /** Error that occurred during the login process. */
  loginError?: Error;

  /** Status of the SIWE message signing process. */
  signMessageStatus: SignMessageStatus;

  /** Error that occurred during the SIWE message signing process. */
  signMessageError?: Error;

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

[version-image]: https://img.shields.io/npm/v/ic-siwe-js
[dl-image]: https://img.shields.io/npm/dw/ic-siwe-js
[npm-link]: https://www.npmjs.com/package/ic-siwe-js
