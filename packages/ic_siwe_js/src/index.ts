import { createStore } from "@xstate/store";
import {
  Ed25519KeyIdentity,
  type DelegationChain,
  DelegationIdentity,
} from "@dfinity/identity";
import { type ActorConfig, type HttpAgentOptions } from "@dfinity/agent";
import { createWalletClient, custom, type WalletClient } from "viem";
import { mainnet } from "viem/chains";
import {
  callGetDelegation,
  callLogin,
  callPrepareLogin,
  createActor,
} from "./siwe-provider";
import { normalizeError } from "./error";
import { createDelegationChain } from "./delegation";
import { clearIdentityFromLocalStorage, loadIdentityFromLocalStorage, saveIdentityToLocalStorage } from "./local-storage";
import type {
  LoginStatus,
  PrepareLoginStatus,
  SignMessageStatus,
} from "./context.type";
import { idlFactory } from "./ic_siwe_provider.did";

export * from "./context.type";
export * from "./service.interface";
export * from "./storage.type";

interface Context {
  isInitializing: boolean;
  prepareLoginStatus: PrepareLoginStatus;
  prepareLoginError?: Error;
  loginStatus: LoginStatus;
  loginError?: Error;
  signMessageStatus: SignMessageStatus;
  signMessageError?: Error;
  identity?: DelegationIdentity;
  identityAddress?: string;
  delegationChain?: DelegationChain;
}

type PartialContext = Partial<Context>;

const initialContext: Context = {
  isInitializing: true,
  prepareLoginStatus: "idle",
  loginStatus: "idle",
  signMessageStatus: "idle",
};

export const siweStateStore = createStore({
  context: initialContext,
  on: {
    updateState: (context, updates: PartialContext) => {
      return { ...context, ...updates };
    },
  },
});

export class SiweManager {
  walletClient?: WalletClient;
  sessionIdentity?: Ed25519KeyIdentity;
  siweMessage?: string;

  /**
   * The SiweManager is the starting point for using the SIWE identity service. It manages the identity state and provides authentication-related functionalities.
   *
   * @param {string} canisterId - The unique identifier of the canister on the Internet Computer network. This ID is used to establish a connection to the canister.
   * @param {HttpAgentOptions} httpAgentOptions - Optional. Configuration options for the HTTP agent used to communicate with the Internet Computer network.
   * @param {ActorConfig} actorOptions - Optional. Configuration options for the actor. These options are passed to the actor upon its creation.
   */
  constructor(
    public canisterId: string,
    public httpAgentOptions?: HttpAgentOptions,
    public actorOptions?: ActorConfig,
  ) {
    try {
      // Attempt to load a stored identity from local storage.
      const [identityAddress, identity, delegationChain] = loadIdentityFromLocalStorage();
      this.updateState({
        identityAddress,
        identity,
        delegationChain,
      });
    } catch (e) {
      const error = normalizeError(e);
      console.error(error.message);
    }
    this.updateState({ isInitializing: false });
  }

  /**
   * Initialize the wallet client if it is not already initialized.
   */
  async setupWalletClient() {
    if (this.walletClient) {
      return;
    }

    if (!window.ethereum) {
      throw new Error("No Ethereum provider found");
    }

    this.walletClient = createWalletClient({
      chain: mainnet,
      transport: custom(window.ethereum),
    });
  }

  /**
   * Convenience method to update the state.
   */
  updateState(updates: PartialContext) {
    siweStateStore.send({ type: "updateState", ...updates });
  }

  getSessionIdentity() {
    if (!this.sessionIdentity) {
      // A random session identity is created on each login.
      this.sessionIdentity = Ed25519KeyIdentity.generate();
    }
    return this.sessionIdentity;
  }


  /**
   * Provide a `WalletClient` instance to the `SiweManager` if you want to
   * override the default wallet client (`window.ethereum`). Must be
   * called before calling `prepareLogin` or `login` to use, for instance, a
   * WalletConnect provider.
   */
  public setWalletClient(walletClient: WalletClient) {
    this.walletClient = walletClient;
  }

  /**
   * Load a SIWE message from the provider canister, to be used for login. Calling prepareLogin
   * is optional, as it will be called automatically on login if not called manually.
   */
  public async prepareLogin(): Promise<string> {
    try {
      await this.setupWalletClient();

      const [account] = await this.walletClient!.getAddresses();
      if (!account) {
        throw new Error(
          "No Ethereum address available. Call login after the user has connected their wallet.",
        );
      }

      this.updateState({
        prepareLoginStatus: "preparing",
        prepareLoginError: undefined,
      });

      const actor = await createActor({
        idlFactory,
        canisterId: this.canisterId,
        httpAgentOptions: this.httpAgentOptions,
        identity: this.getSessionIdentity(),
        actorOptions: this.actorOptions,
      });

      const response = await callPrepareLogin(actor, account);
      // Store SIWE message for later use during sign-in.
      this.siweMessage = response;
      this.updateState({
        prepareLoginStatus: "success",
      });

      return response;
    } catch (e) {
      const error = normalizeError(e);
      console.error(error);
      this.updateState({
        prepareLoginStatus: "error",
        prepareLoginError: error,
      });
      throw error;
    }
  }

  /**
   * Initiates the login process. If a SIWE message is not already available, it will be
   * generated by calling prepareLogin.
   */
  public async login(): Promise<DelegationIdentity | undefined> {
    try {
      if (
        siweStateStore.getSnapshot().context.prepareLoginStatus === "preparing"
      ) {
        throw new Error("Don't call login while prepareLogin is in progress");
      }

      if (siweStateStore.getSnapshot().context.loginStatus === "logging-in") {
        throw new Error("Don't call login while login is in progress");
      }

      await this.setupWalletClient();

      // Get the session identity or create a new if no one exists
      const sessionIdentity = this.getSessionIdentity();

      const [account] = await this.walletClient!.getAddresses();
      if (!account) {
        throw new Error(
          "No Ethereum address available. Call login after the user has connected their wallet.",
        );
      }

      this.updateState({
        loginStatus: "logging-in",
        loginError: undefined,
        signMessageError: undefined,
      });

      // Ensure we have a SIWE message, fetching if necessary.
      const siweMessage = this.siweMessage ?? (this.siweMessage = await this.prepareLogin());
      if (!siweMessage) {
        throw new Error("Prepare login failed did not return a SIWE message.");
      }

      this.updateState({
        signMessageStatus: "pending",
      });

      let signature;
      try {
        signature = await this.walletClient?.signMessage({
          account,
          message: siweMessage,
        });
        if (!signature) {
          throw new Error("signMessage returned no data.");
        }
      } catch (e) {
        const error = normalizeError(e);
        console.error(error);
        this.updateState({
          signMessageStatus: "error",
          signMessageError: error,
        });
        throw error;
      }

      this.updateState({
        signMessageStatus: "success",
      });


      const actor = await createActor({
        idlFactory,
        canisterId: this.canisterId,
        httpAgentOptions: this.httpAgentOptions,
        identity: sessionIdentity,
        actorOptions: this.actorOptions,
      });

      const sessionPublicKey = sessionIdentity.getPublicKey().toDer();
      const loginOkResponse = await callLogin(
        actor,
        signature,
        account,
        sessionPublicKey,
      );

      // Call the backend's siwe_get_delegation method to get the delegation.
      const getDelegationResponse = await callGetDelegation(
        actor,
        account,
        sessionPublicKey,
        loginOkResponse.expiration,
      );

      // Create a new delegation chain from the delegation.
      const delegationChain = createDelegationChain(
        getDelegationResponse,
        loginOkResponse.user_canister_pubkey,
      );

      // Create a new delegation identity from the session identity and the
      // delegation chain.
      const identity = DelegationIdentity.fromDelegation(
        sessionIdentity,
        delegationChain,
      );

      // Save the identity for future use.
      saveIdentityToLocalStorage(account, sessionIdentity, delegationChain);

      this.updateState({
        loginStatus: "success",
        identityAddress: account,
        identity,
        delegationChain,
      });

      return identity;
    } catch (e) {
      const error = normalizeError(e);
      console.error(error);
      this.updateState({
        loginStatus: "error",
        loginError: error,
      });
      throw error;
    }
  }

  /**
   * Clears the state and local storage. Effectively "logs the user out".
   */
  public clear() {
    this.updateState({
      prepareLoginStatus: "idle",
      prepareLoginError: undefined,
      loginStatus: "idle",
      loginError: undefined,
      signMessageStatus: "idle",
      signMessageError: undefined,
      identity: undefined,
      identityAddress: undefined,
      delegationChain: undefined,
    });
    this.sessionIdentity = undefined;
    this.siweMessage = undefined;
    clearIdentityFromLocalStorage();
  }
}
