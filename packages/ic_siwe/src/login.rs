use candid::CandidType;
use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::{
    delegation::prepare_delegation,
    eth::{recover_eth_address, validate_eth_address, validate_eth_signature},
    settings::get_settings,
    siwe::{get_siwe_message, prune_expired_siwe_messages, remove_siwe_message},
};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LoginOkResponse {
    pub expiration: u64,
    pub user_canister_pubkey: ByteBuf,
}

pub fn login(
    signature: &str,
    address: &str,
    session_key: ByteBuf,
) -> Result<LoginOkResponse, String> {
    validate_eth_signature(signature)?;
    validate_eth_address(address)?;

    prune_expired_siwe_messages();

    let message = get_siwe_message(address)?;
    let message_string: String = message.clone().into();

    let recovered_address = recover_eth_address(&message_string, signature)?;
    if recovered_address != address {
        return Err(String::from("Signature verification failed"));
    }

    let settings = get_settings()?;
    let expiration = message
        .issued_at
        .saturating_add(settings.session_expires_in);

    let user_canister_pubkey = prepare_delegation(address, session_key, &message)?;

    remove_siwe_message(address);

    Ok(LoginOkResponse {
        expiration,
        user_canister_pubkey,
    })
}
