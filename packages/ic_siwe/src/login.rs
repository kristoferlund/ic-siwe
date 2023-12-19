use serde_bytes::ByteBuf;

use crate::utils::{
    delegation::prepare_delegation,
    eth::{recover_eth_address, validate_eth_address, validate_eth_signature},
    siwe::{get_siwe_message, prune_expired_siwe_messages, remove_siwe_message},
};

pub fn login(signature: &str, address: &str, session_key: ByteBuf) -> Result<ByteBuf, String> {
    validate_eth_signature(signature)?;
    validate_eth_address(address)?;

    prune_expired_siwe_messages();

    let message = get_siwe_message(address)?;
    let message_string: String = message.clone().into();

    let recovered_address = recover_eth_address(&message_string, signature)?;
    if recovered_address != address {
        return Err(String::from("Signature verification failed"));
    }

    remove_siwe_message(address);

    prepare_delegation(address, session_key, &message)
}
