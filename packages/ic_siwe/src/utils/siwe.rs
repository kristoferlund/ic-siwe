use crate::{
    types::{settings::get_settings, siwe_message::SiweMessage},
    STATE,
};

use super::{rand::generate_nonce, time::get_current_time};

/// Create SIWE message for the given address.
pub(crate) fn create_siwe_message(address: &str) -> Result<SiweMessage, String> {
    let settings = get_settings()?;
    let nonce = generate_nonce()?;

    let message = SiweMessage {
        scheme: settings.scheme,
        domain: settings.domain,
        address: address.to_string(),
        statement: settings.statement,
        uri: settings.uri,
        version: 1,
        chain_id: settings.chain_id,
        nonce: hex::encode(nonce),
        issued_at: get_current_time(),
        expiration_time: get_current_time().saturating_add(settings.sign_in_expires_in),
    };

    Ok(message)
}

/// Removes SIWE messages that have exceeded their time to live.
pub(crate) fn prune_expired_siwe_messages() {
    let current_time = get_current_time();

    STATE.with(|state| {
        state
            .siwe_messages
            .borrow_mut()
            .retain(|_, message| message.expiration_time > current_time);
    });
}

/// Adds a SIWE message to state.
pub(crate) fn add_siwe_message(message: SiweMessage) {
    STATE.with(|state| {
        state
            .siwe_messages
            .borrow_mut()
            .insert(message.address.as_bytes().to_vec(), message);
    });
}

/// Fetches the SIWE message associated with the provided address.
pub(crate) fn get_siwe_message(address: &str) -> Result<SiweMessage, String> {
    STATE.with(|state| {
        state
            .siwe_messages
            .borrow()
            .get(address.as_bytes())
            .cloned()
            .ok_or_else(|| String::from("Message not found for the given address"))
    })
}
