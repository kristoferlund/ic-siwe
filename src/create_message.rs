use crate::{
    types::{settings::get_settings, siwe_message::SiweMessage},
    utils::{rand::generate_nonce, time::get_current_time},
    SIGN_IN_MESSAGES,
};

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

    let settings = get_settings()?;

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
        issued_at: get_current_time(),
        expiration_time: get_current_time() + settings.sign_in_expires_in,
    };

    SIGN_IN_MESSAGES.with_borrow_mut(|map| {
        map.insert(address.as_bytes().to_vec(), message.clone());
    });

    Ok(message)
}

pub fn create_message_as_erc_4361(address: String) -> Result<String, String> {
    let message = create_message(address)?;

    Ok(message.to_erc_4361())
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

#[cfg(test)]
mod tests {
    use siwe::Message;

    use crate::{types::settings::SettingsBuilder, SETTINGS};

    use super::*;

    const VALID_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    fn init() {
        let settings = SettingsBuilder::new("localhost", "http://localhost:8080")
            .scheme("http")
            .statement("Login to the app")
            .build()
            .unwrap();

        SETTINGS.with(|s| {
            *s.borrow_mut() = Some(settings);
        });
    }

    #[test]
    fn test_create_message_no_settings() {
        let result = create_message(VALID_ADDRESS.to_string());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Settings are not initialized");
    }

    #[test]
    fn test_create_message_success() {
        init();

        let result = create_message(VALID_ADDRESS.to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_message_invalid_address() {
        init();

        let invalid_address = "0xG".to_string() + &"1".repeat(39); // A mock invalid Ethereum address
        let result = create_message(invalid_address);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid hex encoding");
    }

    #[test]
    fn test_create_message_invalid_hex_encoding() {
        init();

        let invalid_address = "0x".to_string() + &"G".repeat(40); // Invalid hex
        let result = create_message(invalid_address);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid hex encoding");
    }

    #[test]
    fn test_create_message_address_too_short() {
        init();

        let invalid_address = "0x".to_string() + &"1".repeat(39); // Too short
        let result = create_message(invalid_address);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid address");
    }

    #[test]
    fn test_create_message_address_too_long() {
        init();

        let invalid_address = "0x".to_string() + &"1".repeat(41); // Too long
        let result = create_message(invalid_address);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid address");
    }

    #[test]
    fn test_create_message_nonce() {
        init();

        let nonce = generate_nonce().expect("Should succeed in generating nonce");

        let result =
            create_message(VALID_ADDRESS.to_string()).expect("Should succeed with valid address");

        // Check if the nonce is set correctly
        assert_eq!(result.nonce, hex::encode(nonce));
    }

    #[test]
    fn test_create_message_expected_message() {
        init();

        let result =
            create_message(VALID_ADDRESS.to_string()).expect("Should succeed with valid address");

        let settings = get_settings().unwrap();

        assert_eq!(result.address, VALID_ADDRESS);
        assert_eq!(result.scheme, settings.scheme);
        assert_eq!(result.domain, settings.domain);
        assert_eq!(result.statement, settings.statement);
        assert_eq!(result.uri, settings.uri);
        assert_eq!(result.version, 1);
        assert_eq!(result.chain_id, settings.chain_id);
        assert_eq!(result.issued_at, get_current_time());
        assert_eq!(
            result.expiration_time,
            get_current_time() + settings.sign_in_expires_in
        );
    }

    #[test]
    fn test_create_message_as_erc_4361() {
        init();

        let result = create_message_as_erc_4361(VALID_ADDRESS.to_string());
        assert!(result.is_ok());

        // Parse the ERC-4361 message and assert it is ok
        let message_result: Result<Message, _> = result.unwrap().parse();
        assert!(message_result.is_ok(), "Parsing the message should succeed");
    }
}
