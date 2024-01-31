/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext } from "react";
import { type ActorConfig, type HttpAgentOptions } from "@dfinity/agent";
import {
  Delegation,
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
  type SignedDelegation,
} from "@dfinity/identity";
import { type ReactNode, useEffect, useState } from "react";
import type { SiweIdentityContextType } from "./context.type";
import { useAccount, useSignMessage } from "wagmi";
import { IDL } from "@dfinity/candid";
import { Principal } from "@dfinity/principal";
import type {
  LoginOkResponse,
  SIWE_IDENTITY_SERVICE,
  SignedDelegation as _SignedDelegation,
} from "./service.interface";
import { clearIdentity, loadIdentity, saveIdentity } from "./local-storage";
import { callGetDelegation, callLogin, createAnonymousActor } from "./ic";
import { asDerEncodedPublicKey, asSignature } from "./utils";
import type { State } from "./state.type";

/**
 * Re-export types
 */
export * from "./context.type";
export * from "./service.interface";
export * from "./storage.type";

/**
 * React context for managing SIWE (Sign-In with Ethereum) identity.
 */
export const SiweIdentityContext = createContext<
  SiweIdentityContextType | undefined
>(undefined);

/**
 * Hook to access the SiweIdentityContext.
 */
export const useSiweIdentity = (): SiweIdentityContextType => {
  const context = useContext(SiweIdentityContext);
  if (!context) {
    throw new Error(
      "useSiweIdentity must be used within an SiweIdentityProvider"
    );
  }
  return context;
};

/**
 * Provider component for the SIWE identity context. Manages identity state and provides authentication-related functionalities.
 *
 * @prop {IDL.InterfaceFactory} idlFactory - Required. The Interface Description Language (IDL) factory for the canister. This factory is used to create an actor interface for the canister.
 * @prop {string} canisterId - Required. The unique identifier of the canister on the Internet Computer network. This ID is used to establish a connection to the canister.
 * @prop {HttpAgentOptions} httpAgentOptions - Optional. Configuration options for the HTTP agent used to communicate with the Internet Computer network.
 * @prop {ActorConfig} actorOptions - Optional. Configuration options for the actor. These options are passed to the actor upon its creation.
 * @prop {ReactNode} children - Required. The child components that the SiweIdentityProvider will wrap. This allows any child component to access the authentication context provided by the SiweIdentityProvider.
 *
 * @example
 * ```tsx
 * import { SiweIdentityProvider } from 'ic-use-siwe-identity';
 * import {canisterId, idlFactory} from "path-to/siwe-enabled-canister/index";
 * import { _SERVICE } from "path-to/siwe-enabled-canister.did";
 *
 * function App() {
 *   return (
 *     <SiweIdentityProvider<_SERVICE>
 *       idlFactory={idlFactory}
 *       canisterId={canisterId}
 *       // ...other props
 *     >
 *       {... your app components}
 *     </App>
 *   );
 * }
 *
 * import { SiweIdentityProvider } from "ic-use-siwe-identity";
 *```
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function SiweIdentityProvider<T extends SIWE_IDENTITY_SERVICE>({
  httpAgentOptions,
  actorOptions,
  idlFactory,
  canisterId,
  children,
}: {
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
}) {
  const {
    signMessage,
    data,
    status: signMessageStatus,
    reset,
    error: signMessageError,
  } = useSignMessage();
  const { address } = useAccount();

  const [state, setState] = useState<State>({
    isInitializing: true,
    prepareLoginStatus: "idle",
    loginStatus: "idle",
  });

  /**
   * Load a SIWE message from the provider, to be used for login. Calling prepareLogin
   * is optional, as it will be called automatically on login if not called manually.
   *
   * @returns {string | undefined} The SIWE message to be signed by the user or undefined if an
   * error occurs. In the case of an error, the error is available in the prepareLoginError property.
   */
  async function prepareLogin(): Promise<string | undefined> {
    if (!state.anonymousActor || !address) {
      throw new Error("Invalid actor or address");
    }

    setState((prevState) => ({
      ...prevState,
      prepareLoginStatus: "preparing",
      prepareLoginError: undefined,
    }));

    try {
      const response = await state.anonymousActor.siwe_prepare_login(address);
      if ("Ok" in response) {
        const siweMessage = response.Ok;
        setState((prevState) => ({
          ...prevState,
          siweMessage,
          prepareLoginStatus: "success",
        }));
        return siweMessage;
      } else {
        throw new Error(response.Err);
      }
    } catch (e) {
      console.error(e);
      setState((prevState) => ({
        ...prevState,
        prepareLoginStatus: "error",
        prepareLoginError: new Error("Unable to prepare login."),
      }));
    }
  }

  /**
   * Initiates the login process. If a SIWE message is not already available, it will be
   * generated by calling prepareLogin.
   *
   * @returns {void} Login does not return anything. If an error occurs, the error is available in
   * the loginError property.
   */
  async function login() {
    if (state.prepareLoginStatus === "preparing") {
      throw new Error("Don't call login while prepareLogin is running.");
    }

    setState((prevState) => ({
      ...prevState,
      loginStatus: "logging-in",
      loginError: undefined,
    }));

    if (state.siweMessage) {
      signMessage({ message: state.siweMessage });
      return;
    }

    const siweMessage = await prepareLogin();
    if (siweMessage) {
      signMessage({ message: siweMessage });
    }
  }

  /**
   * Clears the state and local storage. Effectively "logs the user out".
   */
  function clear() {
    setState((prevState) => ({
      ...prevState,
      isInitializing: false,
      prepareLoginStatus: "idle",
      prepareLoginError: undefined,
      siweMessage: undefined,
      loginStatus: "idle",
      loginError: undefined,
      identity: undefined,
      identityAddress: undefined,
      delegationChain: undefined,
    }));
    clearIdentity();
  }

  /**
   * Load the identity from local storage on mount.
   */
  useEffect(() => {
    try {
      const [a, i, d] = loadIdentity();
      setState((prevState) => ({
        ...prevState,
        identityAddress: a,
        identity: i,
        delegationChain: d,
        isInitializing: false,
      }));
    } catch (e) {
      if (e instanceof Error) {
        console.log("Could not load identity from local storage: ", e.message);
      }
      setState((prevState) => ({
        ...prevState,
        isInitializing: false,
      }));
    }
  }, []);

  /**
   * On address change, reset the state. Action is conditional on state.isInitializing
   * being false.
   */
  useEffect(() => {
    if (state.isInitializing) return;
    clear();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address]);

  /**
   * Create an anonymous actor on mount. This actor is used during the login
   * process.
   */
  useEffect(() => {
    const a = createAnonymousActor({
      idlFactory,
      canisterId,
      httpAgentOptions,
      actorOptions,
    });
    setState((prevState) => ({
      ...prevState,
      anonymousActor: a,
    }));
  }, [idlFactory, canisterId, httpAgentOptions, actorOptions]);

  /**
   * Once a signed SIWE message is received, login to the backend.
   */
  useEffect(() => {
    (async () => {
      if (!data || !address || !state.anonymousActor) return;
      if (state.loginStatus === "logging-in") {
        // Generate a new session identity.
        const sessionIdentity = Ed25519KeyIdentity.generate();
        const sessionPublicKey = sessionIdentity.getPublicKey().toDer();

        // Call the backend's login method with the signed SIWE message.
        let loginOkResponse: LoginOkResponse;
        try {
          loginOkResponse = await callLogin(
            state.anonymousActor,
            data,
            address,
            sessionPublicKey
          );
        } catch (e) {
          if (e instanceof Error) {
            console.error(e);
          }
          setState((prevState) => ({
            ...prevState,
            siweMessage: undefined,
            loginStatus: "error",
            loginError: new Error("Unable to login."),
          }));
          return;
        }

        // Call the backend's siwe_get_delegation method to get the delegation.
        let signedDelegation: _SignedDelegation;
        try {
          signedDelegation = await callGetDelegation(
            state.anonymousActor,
            address,
            sessionPublicKey,
            loginOkResponse.expiration
          );
        } catch (e) {
          if (e instanceof Error) {
            console.error(e);
          }
          setState((prevState) => ({
            ...prevState,
            siweMessage: undefined,
            loginStatus: "error",
            loginError: new Error("Login: Unable to get identity."),
          }));
          return;
        }

        // Create a new delegation chain from the delegation.
        const delegations: SignedDelegation[] = [
          {
            delegation: new Delegation(
              (signedDelegation.delegation.pubkey as Uint8Array).buffer,
              signedDelegation.delegation.expiration,
              signedDelegation.delegation.targets[0] as Principal[]
            ),
            signature: asSignature(signedDelegation.signature),
          },
        ];
        const delegationChain = DelegationChain.fromDelegations(
          delegations,
          asDerEncodedPublicKey(loginOkResponse.user_canister_pubkey)
        );

        // Create a new delegation identity from the session identity and the
        // delegation chain.
        const identity = DelegationIdentity.fromDelegation(
          sessionIdentity,
          delegationChain
        );

        // Save the identity to local storage.
        saveIdentity(address, sessionIdentity, delegationChain);

        // Set the identity in state.
        setState((prevState) => ({
          ...prevState,
          loginStatus: "success",
          identityAddress: address,
          identity,
          delegationChain,
        }));

        // Reset the signMessage hook so that it can be used again.
        reset();
      }
    })();
  }, [data, address, state.loginStatus, state.anonymousActor, reset]);

  /**
   * If an error occurs during the message signing, stop the login process. One such
   * error is when the user cancels the login.
   */
  useEffect(() => {
    if (signMessageStatus === "error") {
      setState((prevState) => ({
        ...prevState,
        loginStatus: "idle",
      }));
    }
  }, [signMessageStatus, setState]);

  return (
    <SiweIdentityContext.Provider
      value={{
        ...state,
        prepareLogin,
        isPreparingLogin: state.prepareLoginStatus === "preparing",
        isPrepareLoginError: state.prepareLoginStatus === "error",
        isPrepareLoginSuccess: state.prepareLoginStatus === "success",
        isPrepareLoginIdle: state.prepareLoginStatus === "idle",
        login,
        isLoggingIn: state.loginStatus === "logging-in",
        isLoginError: state.loginStatus === "error",
        isLoginSuccess: state.loginStatus === "success",
        isLoginIdle: state.loginStatus === "idle",
        signMessageStatus,
        signMessageError,
        clear,
      }}
    >
      {children}
    </SiweIdentityContext.Provider>
  );
}
