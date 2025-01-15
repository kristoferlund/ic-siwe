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
export async function createAnonymousActor({
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
  const shouldFetchRootKey = process.env.DFX_NETWORK !== "ic";
  const agent = await HttpAgent.create({
    ...httpAgentOptions,
    shouldFetchRootKey,
  });
  return Actor.createActor<SIWE_IDENTITY_SERVICE>(idlFactory, {
    agent,
    canisterId,
    ...actorOptions,
  });
}

export async function callPrepareLogin(
  anonymousActor: ActorSubclass<SIWE_IDENTITY_SERVICE>,
  address: `0x${string}` | undefined,
) {
  if (!anonymousActor || !address) {
    throw new Error("Invalid actor or address");
  }

  const response = await anonymousActor.siwe_prepare_login(address);

  if ("Err" in response) {
    throw new Error(response.Err);
  }

  return response.Ok;
}

/**
 * Logs in the user by sending a signed SIWE message to the backend.
 */
export async function callLogin(
  anonymousActor: ActorSubclass<SIWE_IDENTITY_SERVICE>,
  data: `0x${string}` | undefined,
  address: `0x${string}` | undefined,
  sessionPublicKey: DerEncodedPublicKey,
  nonce: string,
) {
  if (!anonymousActor || !data || !address) {
    throw new Error("Invalid actor, data or address");
  }

  const loginReponse = await anonymousActor.siwe_login(
    data,
    address,
    new Uint8Array(sessionPublicKey),
    nonce,
  );

  if ("Err" in loginReponse) {
    throw new Error(loginReponse.Err);
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
  expiration: bigint,
) {
  if (!anonymousActor || !address) {
    throw new Error("Invalid actor or address");
  }

  const response = await anonymousActor.siwe_get_delegation(
    address,
    new Uint8Array(sessionPublicKey),
    expiration,
  );

  if ("Err" in response) {
    throw new Error(response.Err);
  }

  return response.Ok;
}
