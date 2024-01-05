import { DelegationChain, DelegationIdentity } from "@dfinity/identity";

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
