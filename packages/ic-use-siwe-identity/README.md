# ic-use-siwe-identity

React hook and context provider for easy frontend integration with SIWE enabled Internet Computer canisters.

...

## Features

...

## Installation

...

## Usage

Wrap your application's root component with SiweIdentityProvider to provide all child components access to the SIWE identity context.

```jsx
import { SiweIdentityProvider } from 'ic-use-siwe-identity';

function App() {
  return (
    <SiweIdentityProvider
      idlFactory={/* IDL Interface Factory */}
      canisterId={/* Canister ID */}
      // ...other props
    >
      {/* Your app components */}
    </App>
  );
}
```

Use the useSiweIdentity hook in your components to access identity-related functionalities:

```jsx
import { useSiweIdentity } from "ic-use-siwe-identity";

function MyComponent() {
  const { login, clear, identity } = useSiweIdentity();
  // ...
}
```
