use crate::{generate_nonce, siwe_message::SiweMessage, SETTINGS, SIWE_MESSAGES};

use ic_cdk::api::time;

/// Creates a SiweMessage based on the given address.
///
/// This function performs all necessary validations and returns a `SiweMessage`
/// if the address is valid.
///
/// # Arguments
///
/// * `address` - The address to be used for creating the `SiweMessage`.
///
/// # Returns
///
/// Returns a `Result` containing the `SiweMessage` or an error message.
pub fn create_message(address: String) -> Result<SiweMessage, String> {
    validate_address(&address)?;

    let settings = SETTINGS
        .get()
        .ok_or_else(|| String::from("Settings are not initialized"))?;

    let nonce = generate_nonce()?;

    let message = SiweMessage {
        scheme: settings.scheme.clone(),
        domain: settings.domain.clone(),
        address: address.clone(),
        statement: settings.statement.clone(),
        uri: settings.uri.clone(),
        version: 1,
        chain_id: settings.chain_id,
        nonce: hex::encode(nonce),
        issued_at: time(),
        expiration_time: time() + settings.expires_in as u64 * 1000000000, // convert to nanoseconds
    };

    SIWE_MESSAGES.with(|map| {
        let mut map_borrowed = map.borrow_mut();
        map_borrowed.insert(address.as_bytes().to_vec(), message.clone());
    });

    Ok(message)
}

/// Validates an Ethereum address based on specific criteria.
///
/// This function checks if the address starts with "0x", has a length of 42 characters,
/// and is a valid hexadecimal string.
///
/// # Arguments
///
/// * `address` - The Ethereum address to be validated.
///
/// # Returns
///
/// Returns a `Result` indicating success or an error message describing the validation failure.
pub fn validate_address(address: &str) -> Result<(), String> {
    if !address.starts_with("0x") || address.len() != 42 {
        return Err(String::from("Invalid address"));
    }

    match hex::decode(&address[2..]) {
        Ok(_) => (),
        Err(_) => return Err(String::from("Invalid hex encoding")),
    };

    Ok(())
}
