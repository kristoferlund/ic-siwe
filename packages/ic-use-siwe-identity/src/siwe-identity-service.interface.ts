import type { ActorMethod } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

export type Address = string;
export type CanisterPublicKey = PublicKey;
export interface Delegation {
  pubkey: PublicKey;
  targets: [] | [Array<Principal>];
  expiration: Timestamp;
}
export type GetDelegationResponse = { Ok: SignedDelegation } | { Err: string };
export interface LoginOkResponse {
  user_canister_pubkey: CanisterPublicKey;
  expiration: Timestamp;
}
export type LoginResponse = { Ok: LoginOkResponse } | { Err: string };
export type PrepareLoginResponse = { Ok: SiweMessage } | { Err: string };
export type PublicKey = Uint8Array | number[];
export type SessionKey = PublicKey;
export interface SignedDelegation {
  signature: Uint8Array | number[];
  delegation: Delegation;
}
export type SiweMessage = string;
export type SiweSignature = string;
export type Timestamp = bigint;
export interface SIWE_IDENTITY_SERVICE {
  get_delegation: ActorMethod<
    [Address, SessionKey, Timestamp],
    GetDelegationResponse
  >;
  login: ActorMethod<[SiweSignature, Address, SessionKey], LoginResponse>;
  prepare_login: ActorMethod<[Address], PrepareLoginResponse>;
}
