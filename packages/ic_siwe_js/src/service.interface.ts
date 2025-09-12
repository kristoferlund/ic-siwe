import type { ActorMethod } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

export type Address = string;
export type PublicKey = Uint8Array;
export type CanisterPublicKey = PublicKey;
export type SessionKey = PublicKey;
export type SiweMessage = string;
export type SiweSignature = string;
export type Timestamp = bigint;

export type PrepareLoginResponse = { Ok: SiweMessage } | { Err: string };

export type LoginResponse = { Ok: LoginOkResponse } | { Err: string };

export interface LoginOkResponse {
  user_canister_pubkey: CanisterPublicKey;
  expiration: Timestamp;
}

export type GetDelegationResponse = { Ok: SignedDelegation } | { Err: string };

export interface Delegation {
  pubkey: PublicKey;
  targets: [] | [Array<Principal>];
  expiration: Timestamp;
}

export interface SignedDelegation {
  signature: Uint8Array;
  delegation: Delegation;
}

export interface SIWE_IDENTITY_SERVICE {
  siwe_prepare_login: ActorMethod<[Address], PrepareLoginResponse>;
  siwe_login: ActorMethod<[SiweSignature, Address, SessionKey], LoginResponse>;
  siwe_get_delegation: ActorMethod<
    [Address, SessionKey, Timestamp],
    GetDelegationResponse
  >;
}
