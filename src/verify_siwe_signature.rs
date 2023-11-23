use crate::{
    types::siwe_message::SiweMessage,
    utils::{eth::recover_address, time::get_current_time},
    SIGN_IN_MESSAGES,
};

/// Verifies the user's signature and address against a previously created SiweMessage. This function
/// can only be called once per SiweMessage. If the user's signature is valid, the SiweMessage is
/// removed from memory.
///
/// # Parameters
///
/// - `signature`: The user's signature.
/// - `address`: The address associated with the user.
///
/// # Returns
///
/// - `Ok(String)`: Returns the user's address if the login process was successful.
/// - `Err`: Descriptive error message if any step fails.
pub fn verify_siwe_signature(signature: &str, address: &str) -> Result<String, String> {
    prune_expired_messages();

    let message: String = get_siwe_message(&address)?.into();
    let recovered_address = recover_address(message.as_str(), signature)?;

    if recovered_address != address {
        return Err(String::from("Signature verification failed"));
    }

    SIGN_IN_MESSAGES.with_borrow_mut(|map| {
        map.remove(address.as_bytes());
    });

    Ok(address.to_string())
}

/// Removes SIWE messages that have exceeded their time to live.
fn prune_expired_messages() {
    let current_time = get_current_time();

    SIGN_IN_MESSAGES.with_borrow_mut(|map| {
        map.retain(|_, message| message.expiration_time > current_time);
    });
}

/// Fetches the SIWE message associated with the provided address.
fn get_siwe_message(address: &str) -> Result<SiweMessage, String> {
    SIGN_IN_MESSAGES
        .with_borrow(|map| map.get(address.as_bytes()).cloned())
        .ok_or_else(|| String::from("Message not found for the given address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_siwe_message, types::settings::SettingsBuilder, SETTINGS};
    use ethers::{
        signers::{LocalWallet, Signer},
        utils::to_checksum,
    };
    use std::time::Duration;

    const VALID_ADDRESS: &str = "0xc2cc7160837714a78ff9f9191ec5a1bb15096179";

    fn init_settings() {
        let settings = SettingsBuilder::new("example.com", "http://example.com")
            .scheme("https")
            .statement("Login to the app")
            .sign_in_expires_in(Duration::from_secs(2).as_nanos() as u64) // Sign in expires in 2 seconds
            .build()
            .unwrap();
        SETTINGS.with(|s| {
            *s.borrow_mut() = Some(settings);
        });
    }

    // Too short signature
    #[tokio::test]
    async fn test_signature_too_short() {
        init_settings();
        create_siwe_message(VALID_ADDRESS).unwrap();
        let invalid_signature = "0";
        let result = verify_siwe_signature(invalid_signature, VALID_ADDRESS);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid signature length");
    }

    #[tokio::test]
    async fn test_incorrect_signature_format() {
        init_settings();
        create_siwe_message(VALID_ADDRESS).unwrap();
        let invalid_signature = "0xÖÖ809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809800"; // A signature with the correct length but incorrect format
        let result = verify_siwe_signature(invalid_signature, VALID_ADDRESS);
        assert!(result.is_err());
        // Assert the specific error message or type you expect for an incorrect format
    }

    // Too long signature
    #[tokio::test]
    async fn test_signature_too_long() {
        init_settings();
        create_siwe_message(VALID_ADDRESS).unwrap();
        let invalid_signature = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_siwe_signature(invalid_signature, VALID_ADDRESS);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid signature length");
    }

    // Test for hex decoding failure
    #[tokio::test]
    async fn test_hex_decoding_failure() {
        init_settings();
        create_siwe_message(VALID_ADDRESS).unwrap();
        let invalid_hex_signature = "GMGM000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // Non-hex characters
        let result = verify_siwe_signature(invalid_hex_signature, VALID_ADDRESS);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Failed to decode signature due to invalid format"
        );
    }

    // Sign in message lives only for 2 seconds
    #[tokio::test]
    async fn test_sign_in_message_expired() {
        init_settings();
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message: String = create_siwe_message(address.as_str()).unwrap().into();
        println!("{:?}", message);
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let result = verify_siwe_signature(signature.as_str(), address.as_str());
        assert!(result.is_ok());

        // Wait for 3 seconds
        tokio::time::sleep(Duration::from_secs(3)).await;

        let result = verify_siwe_signature(signature.as_str(), address.as_str()); // Attempt to login again
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Message not found for the given address"
        );
    }

    // A valid signature but with a different address
    #[tokio::test]
    async fn test_recovery_address_mismatch() {
        init_settings();
        create_siwe_message(VALID_ADDRESS).unwrap();
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message: String = create_siwe_message(address.as_str()).unwrap().into();
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let result = verify_siwe_signature(signature.as_str(), VALID_ADDRESS);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Signature verification failed");
    }

    #[tokio::test]
    async fn test_invalid_recovery_byte() {
        init_settings();
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message: String = create_siwe_message(address.as_str()).unwrap().into();
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let manipulated_signature = format!("{}0000000000", &signature[..signature.len() - 10]);
        let result = verify_siwe_signature(manipulated_signature.as_str(), address.as_str());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid recovery byte");
    }

    #[tokio::test]
    async fn test_signature_manipulation() {
        init_settings();
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message: String = create_siwe_message(address.as_str()).unwrap().into();
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let manipulated_signature = format!("9999{}", &signature[4..]);
        let result = verify_siwe_signature(manipulated_signature.as_str(), address.as_str());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_address() {
        init_settings();
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message: String = create_siwe_message(address.as_str()).unwrap().into();
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let result = verify_siwe_signature(signature.as_str(), "0x123"); // Wrong address
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Message not found for the given address"
        );
    }

    #[tokio::test]
    async fn test_successful_login() {
        init_settings();
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message: String = create_siwe_message(address.as_str()).unwrap().into();
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let result = verify_siwe_signature(signature.as_str(), address.as_str());
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_replay_attack() {
        init_settings();

        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message: String = create_siwe_message(address.as_str()).unwrap().into();
        let signature = wallet.sign_message(message).await.unwrap().to_string();

        let first_attempt = verify_siwe_signature(signature.as_str(), address.as_str());
        assert!(first_attempt.is_ok());

        let second_attempt = verify_siwe_signature(signature.as_str(), address.as_str());
        assert!(second_attempt.is_err());
        assert_eq!(
            second_attempt.unwrap_err(),
            "Message not found for the given address"
        );
    }
}
