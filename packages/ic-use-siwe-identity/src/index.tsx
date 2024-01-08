/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext } from "react";
import {
  type ActorConfig,
  type ActorSubclass,
  type HttpAgentOptions,
} from "@dfinity/agent";
import {
  Delegation,
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
  type SignedDelegation,
} from "@dfinity/identity";
import { type ReactNode, useEffect, useState } from "react";
import type { SiweIdentityContextType } from "./siwe-identity-context.type";
import { useAccount, useSignMessage } from "wagmi";
import { IDL } from "@dfinity/candid";
import { Principal } from "@dfinity/principal";
import type { SIWE_IDENTITY_SERVICE } from "./siwe-identity-service.interface";
import { clearIdentity, loadIdentity, saveIdentity } from "./local-storage";
import { callGetDelegation, callLogin, createAnonymousActor } from "./ic";
import { asDerEncodedPublicKey, asSignature } from "./utils";

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
  const { signMessage, data, status, reset } = useSignMessage();
  const { address } = useAccount();

  const [state, setState] = useState({
    anonymousActor: undefined as
      | ActorSubclass<SIWE_IDENTITY_SERVICE>
      | undefined,
    isLoading: true,
    isLoggingIn: false,
    identity: undefined as DelegationIdentity | undefined,
    identityAddress: undefined as string | undefined,
    delegationChain: undefined as DelegationChain | undefined,
  });

  /**
   * Initiates the login process by requesting a SIWE message from the backend.
   */
  function login() {
    if (!state.anonymousActor || !address) return;
    setState((prevState) => ({
      ...prevState,
      isLoggingIn: true,
    }));
    state.anonymousActor.prepare_login(address).then((response) => {
      if ("Ok" in response) {
        const siweMessage = response.Ok;
        signMessage({ message: siweMessage });
      } else {
        console.error(response.Err);
        setState((prevState) => ({
          ...prevState,
          isLoggingIn: false,
        }));
      }
    });
  }

  /**
   * Clears the identity from the state and local storage. Effectively "logs the
   * user out".
   */
  function clear() {
    setState((prevState) => ({
      ...prevState,
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
        isLoading: false,
      }));
    } catch (e) {
      console.error("Error loading identity:", e);
      setState((prevState) => ({
        ...prevState,
        isLoading: false,
      }));
    }
  }, []);

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
      if (state.isLoggingIn) {
        // Generate a new session identity.
        const sessionIdentity = Ed25519KeyIdentity.generate();
        const sessionPublicKey = sessionIdentity.getPublicKey().toDer();

        // Call the backend's login method with the signed SIWE message.
        const loginOkResponse = await callLogin(
          state.anonymousActor,
          data,
          address,
          sessionPublicKey
        );
        if (!loginOkResponse) {
          setState((prevState) => ({
            ...prevState,
            isLoggingIn: false,
          }));
          return;
        }

        // Call the backend's get_delegation method to get the delegation.
        const signedDelegation = await callGetDelegation(
          state.anonymousActor,
          address,
          sessionPublicKey,
          loginOkResponse.expiration
        );
        if (!signedDelegation) {
          setState((prevState) => ({
            ...prevState,
            isLoggingIn: false,
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
          isLoggingIn: false,
          identityAddress: address,
          identity,
          delegationChain,
        }));

        // Reset the signMessage hook so that it can be used again.
        reset();
      }
    })();
  }, [data, address, state.isLoggingIn, state.anonymousActor, reset]);

  /**
   * If an error occurs during the message signing, stop the login process. One such
   * error is when the user cancels the login.
   */
  useEffect(() => {
    if (status === "error") {
      setState((prevState) => ({
        ...prevState,
        isLoggingIn: false,
      }));
    }
  }, [status, setState]);

  return (
    <SiweIdentityContext.Provider
      value={{
        login,
        clear,
        isLoading: state.isLoading,
        isLoggingIn: state.isLoggingIn,
        signMessageStatus: status,
        delegationChain: state.delegationChain,
        identity: state.identity,
        identityAddress: state.identityAddress,
      }}
    >
      {children}
    </SiweIdentityContext.Provider>
  );
}
