import type { DelegationChain, DelegationIdentity } from "@dfinity/identity";

import type { ActorSubclass } from "@dfinity/agent";
import type { SIWE_IDENTITY_SERVICE } from "./service.interface";

export type State = {
  anonymousActor?: ActorSubclass<SIWE_IDENTITY_SERVICE>;
  isLoading: boolean;
  siweMessage?: string;
  isLoggingIn: boolean;
  identity?: DelegationIdentity;
  identityAddress?: string;
  delegationChain?: DelegationChain;
};
