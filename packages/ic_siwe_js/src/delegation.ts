import type { DerEncodedPublicKey, Signature } from "@dfinity/agent";
import type { PublicKey } from "./service.interface";
import { Principal } from "@dfinity/principal";
import { Delegation } from "@dfinity/identity";
import { DelegationChain, type SignedDelegation } from "@dfinity/identity";
import type { SignedDelegation as ServiceSignedDelegation } from "./service.interface";

export function createDelegationChain(
  signedDelegation: ServiceSignedDelegation,
  publicKey: PublicKey
) {
  const delegations: SignedDelegation[] = [
    {
      delegation: new Delegation(
        signedDelegation.delegation.pubkey as Uint8Array,
        signedDelegation.delegation.expiration,
        signedDelegation.delegation.targets[0] as Principal[]
      ),
      signature: signedDelegation.signature as Signature,
    },
  ];
  return DelegationChain.fromDelegations(
    delegations,
    publicKey as DerEncodedPublicKey
  );
}
