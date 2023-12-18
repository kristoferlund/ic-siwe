use crate::{
    types::siwe_message::SiweMessage,
    utils::{
        eth::validate_eth_address,
        siwe::{add_siwe_message, create_siwe_message, prune_expired_siwe_messages},
    },
};

pub fn prepare_login(address: &str) -> Result<SiweMessage, String> {
    validate_eth_address(&address)?;

    prune_expired_siwe_messages();

    let message = create_siwe_message(&address)?;

    add_siwe_message(message.clone());

    Ok(message)
}

#[cfg(test)]
mod tests {
    use crate::{
        types::settings::{get_settings, SettingsBuilder},
        SETTINGS,
    };

    use super::*;

    const VALID_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    fn init() {
        let settings = SettingsBuilder::new("localhost", "http://localhost:8080", "salt")
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
        let result = prepare_login(VALID_ADDRESS);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Settings are not initialized");
    }

    #[test]
    fn test_create_message_success() {
        init();

        let result = prepare_login(VALID_ADDRESS);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_message_invalid_address() {
        init();

        let invalid_address = "0xG".to_owned() + &"1".repeat(39); // A mock invalid Ethereum address
        let result = prepare_login(invalid_address.as_str());
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
        let result = prepare_login(invalid_address.as_str());
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
        let result = prepare_login(invalid_address.as_str());
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
        let result = prepare_login(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long"
        );
    }

    #[test]
    fn test_create_message_expected_message() {
        init();

        let result = prepare_login(VALID_ADDRESS).expect("Should succeed with valid address");

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
