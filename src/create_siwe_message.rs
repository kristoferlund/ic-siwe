use crate::{
    types::{settings::get_settings, siwe_message::SiweMessage},
    utils::{rand::generate_nonce, time::get_current_time},
    SIGN_IN_MESSAGES,
};

/// Creates a SiweMessage for the given address.
/// Validates the address, fetches settings, generates a nonce, and constructs the SiweMessage.
///
/// # Arguments
///
/// * `address` - The Ethereum address for which to create the SiweMessage.
///
/// # Returns
///
/// `Result<SiweMessage, String>` - SiweMessage on success, or an error message on failure.
pub fn create_siwe_message(address: &str) -> Result<SiweMessage, String> {
    validate_address(&address)?;

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
        expiration_time: get_current_time() + settings.sign_in_expires_in,
    };

    SIGN_IN_MESSAGES.with_borrow_mut(|map| {
        map.insert(message.address.as_bytes().to_vec(), message.clone());
    });

    Ok(message)
}

/// Validates an Ethereum address by checking its length and hex encoding.
fn validate_address(address: &str) -> Result<(), String> {
    if !address.starts_with("0x") || address.len() != 42 {
        return Err(String::from(
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long",
        ));
    }

    hex::decode(&address[2..]).map_err(|_| "Invalid Ethereum address: Hex decoding failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
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
        let result = create_siwe_message(VALID_ADDRESS);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Settings are not initialized");
    }

    #[test]
    fn test_create_message_success() {
        init();

        let result = create_siwe_message(VALID_ADDRESS);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_message_invalid_address() {
        init();

        let invalid_address = "0xG".to_owned() + &"1".repeat(39); // A mock invalid Ethereum address
        let result = create_siwe_message(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Hex decoding failed"
        );
    }

    #[test]
    fn test_create_message_invalid_hex_encoding() {
        init();

        let invalid_address = "0x".to_owned() + &"G".repeat(40); // Invalid hex
        let result = create_siwe_message(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Hex decoding failed"
        );
    }

    #[test]
    fn test_create_message_address_too_short() {
        init();

        let invalid_address = "0x".to_owned() + &"1".repeat(39); // Too short
        let result = create_siwe_message(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long"
        );
    }

    #[test]
    fn test_create_message_address_too_long() {
        init();

        let invalid_address = "0x".to_owned() + &"1".repeat(41); // Too long
        let result = create_siwe_message(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long"
        );
    }

    #[test]
    fn test_create_message_expected_message() {
        init();

        let result = create_siwe_message(VALID_ADDRESS).expect("Should succeed with valid address");

        let settings = get_settings().unwrap();

        assert_eq!(result.address, VALID_ADDRESS);
        assert_eq!(result.scheme, settings.scheme);
        assert_eq!(result.domain, settings.domain);
        assert_eq!(result.statement, settings.statement);
        assert_eq!(result.uri, settings.uri);
        assert_eq!(result.version, 1);
        assert_eq!(result.chain_id, settings.chain_id);
    }

    // #[test]
    // fn test_create_message_as_erc_4361() {
    //     init();

    //     let result = create_message_as_erc_4361(VALID_ADDRESS);
    //     assert!(result.is_ok());

    //     // Parse the ERC-4361 message and assert it is ok
    //     let message_result: Result<Message, _> = result.unwrap().parse();
    //     assert!(message_result.is_ok(), "Parsing the message should succeed");
    // }
}
