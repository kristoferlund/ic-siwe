use candid::{CandidType, Principal};
use serde::Deserialize;
use serde_bytes::ByteBuf;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignedDelegationCandidType {
    pub delegation: DelegationCandidType,
    pub signature: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DelegationCandidType {
    pub pubkey: ByteBuf,
    pub expiration: u64,
    pub targets: Option<Vec<Principal>>,
}
