import {
  HttpAgent,
  type ActorConfig,
  type HttpAgentOptions,
  Actor,
  type DerEncodedPublicKey,
  type ActorSubclass,
} from "@dfinity/agent";
import type { IDL } from "@dfinity/candid";
import type { SIWE_IDENTITY_SERVICE } from "./service.interface";

/**
 * Creates an anonymous actor for interactions with the Internet Computer.
 * This is used primarily for the initial authentication process.
 */
export function createAnonymousActor({
  idlFactory,
  canisterId,
  httpAgentOptions,
  actorOptions,
}: {
  idlFactory: IDL.InterfaceFactory;
  canisterId: string;
  httpAgentOptions?: HttpAgentOptions;
  actorOptions?: ActorConfig;
}) {
  if (!idlFactory || !canisterId) return;
  const agent = new HttpAgent({ ...httpAgentOptions });

  if (process.env.DFX_NETWORK !== "ic") {
    agent.fetchRootKey().catch((err) => {
      console.warn(
        "Unable to fetch root key. Check to ensure that your local replica is running"
      );
      console.error(err);
    });
  }

  return Actor.createActor<SIWE_IDENTITY_SERVICE>(idlFactory, {
    agent,
    canisterId,
    ...actorOptions,
  });
}

/**
 * Logs in the user by sending a signed SIWE message to the backend.
 */
export async function callLogin(
  anonymousActor: ActorSubclass<SIWE_IDENTITY_SERVICE>,
  data: `0x${string}` | undefined,
  address: `0x${string}` | undefined,
  sessionPublicKey: DerEncodedPublicKey
) {
  if (!anonymousActor || !data || !address) return;

  const loginReponse = await anonymousActor.login(
    data,
    address,
    new Uint8Array(sessionPublicKey)
  );

  if ("Err" in loginReponse) {
    console.error(loginReponse.Err);
    return;
  }

  return loginReponse.Ok;
}

/**
 * Retrieves a delegation from the backend for the current session.
 */
export async function callGetDelegation(
  anonymousActor: ActorSubclass<SIWE_IDENTITY_SERVICE>,
  address: `0x${string}` | undefined,
  sessionPublicKey: DerEncodedPublicKey,
  expiration: bigint
) {
  if (!anonymousActor || !address) return;

  const response = await anonymousActor.get_delegation(
    address,
    new Uint8Array(sessionPublicKey),
    expiration
  );

  if ("Err" in response) {
    console.error(response.Err);
    return;
  }

  return response.Ok;
}
