import { DelegationChain, DelegationIdentity } from "@dfinity/identity";

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
