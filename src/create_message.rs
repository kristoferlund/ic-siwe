use crate::{generate_nonce, siwe_message::SiweMessage, SETTINGS, SIWE_MESSAGES};

#[cfg(not(test))]
fn get_current_time() -> u64 {
    // This code is used in production, where ic_cdk::api::time() is available
    ic_cdk::api::time()
}

#[cfg(test)]
fn get_current_time() -> u64 {
    // In tests, return a fixed time or a mock time as needed
    // For example, you might have a static variable in your tests that determines the mock time
    123456789 // replace with a suitable way to get mock time for your tests
}

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
        .with(|settings| settings.borrow().as_ref().cloned())
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
        issued_at: get_current_time(),
        expiration_time: get_current_time() + settings.expires_in as u64 * 1000000000, // convert to nanoseconds
    };

    SIWE_MESSAGES.with_borrow_mut(|map| {
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
    use crate::siwe_settings::SiweSettingsBuilder;

    use super::*;

    fn init() {
        let settings =
            SiweSettingsBuilder::new("localhost".to_string(), "http://localhost:8080".to_string())
                .scheme("http".to_string())
                .statement("Login to the app".to_string())
                .build();

        SETTINGS.with(|s| {
            *s.borrow_mut() = Some(settings);
        });
    }

    #[test]
    fn test_create_message_no_settings() {
        let valid_address = "0x".to_string() + &"1".repeat(40);
        let result = create_message(valid_address);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Settings are not initialized");
    }

    #[test]
    fn test_create_message_success() {
        init();

        let valid_address = "0x".to_string() + &"1".repeat(40); // A mock valid Ethereum address
        let result = create_message(valid_address);
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
}
