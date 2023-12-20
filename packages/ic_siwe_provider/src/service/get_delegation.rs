use ic_cdk::query;
use ic_siwe::delegation::SignedDelegationCandidType;
use serde_bytes::ByteBuf;

// Once logged in, the user can fetch the delegation to be used for authentication.
#[query]
fn get_delegation(
    address: String,
    session_key: ByteBuf,
    expiration: u64,
) -> Result<SignedDelegationCandidType, String> {
    ic_siwe::login::get_delegation(&address, session_key, expiration)
}
