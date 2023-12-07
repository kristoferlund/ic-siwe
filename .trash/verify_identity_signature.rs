use crate::{create_identity_message, utils::ecdsa::recover_address};

pub fn verify_identity_signature(signature: &str, address: &str) -> Result<String, String> {
    // Create an identity message based on the provided address
    let identity_message = create_identity_message(address)?;

    // Recover the address from the signature and the identity message
    let recovered_address = recover_address(identity_message.as_str(), signature)?;
    if recovered_address != address {
        // If the recovered address does not match the provided address, return an error
        return Err("Signature verification failed".to_string());
    }

    Ok(address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{types::settings::SettingsBuilder, SETTINGS};
    use ethers::{
        signers::{LocalWallet, Signer},
        utils::to_checksum,
    };
    use std::time::Duration;

    const VALID_ADDRESS: &str = "0xc2cc7160837714a78ff9f9191ec5a1bb15096179";

    fn init_settings() {
        let settings = SettingsBuilder::new("example.com", "http://example.com", "salt")
            .scheme("https")
            .statement("Login to the app")
            .sign_in_expires_in(Duration::from_secs(2).as_nanos() as u64) // Sign in expires in 2 seconds
            .build()
            .unwrap();
        SETTINGS.with(|s| {
            *s.borrow_mut() = Some(settings);
        });
    }

    async fn create_signed_message() -> (String, String) {
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message: String = create_identity_message(address.as_str()).unwrap().into();
        let signature = wallet.sign_message(message.clone()).await.unwrap();
        (address, signature.to_string())
    }

    async fn verify_signature(signature: &str, address: &str) -> Result<String, String> {
        init_settings();
        verify_identity_signature(signature, address)
    }
    // Too short signature
    #[tokio::test]
    async fn test_signature_too_short() {
        let result = verify_signature("0", VALID_ADDRESS).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid signature length");
    }

    #[tokio::test]
    async fn test_incorrect_signature_format() {
        init_settings();
        let invalid_signature = "0xÖÖ809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809800"; // A signature with the correct length but incorrect format
        let result = verify_identity_signature(invalid_signature, VALID_ADDRESS);
        assert!(result.is_err());
    }

    // Too long signature
    #[tokio::test]
    async fn test_signature_too_long() {
        let long_signature = "0".repeat(135);
        let result = verify_signature(long_signature.as_str(), VALID_ADDRESS).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid signature length");
    }

    // Test for hex decoding failure
    #[tokio::test]
    async fn test_hex_decoding_failure() {
        init_settings();
        let invalid_hex_signature = "GMGM000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // Non-hex characters
        let result = verify_identity_signature(invalid_hex_signature, VALID_ADDRESS);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Decoding error: Invalid character 'G' at position 0"
        );
    }

    // A valid signature but with a different address
    #[tokio::test]
    async fn test_recovery_address_mismatch() {
        init_settings();
        let (_, signature) = create_signed_message().await;
        let result = verify_signature(signature.as_str(), VALID_ADDRESS).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Signature verification failed");
    }

    #[tokio::test]
    async fn test_invalid_recovery_byte() {
        init_settings();
        let (address, signature) = create_signed_message().await;
        let manipulated_signature = format!("{}0000000000", &signature[..signature.len() - 10]);
        let result = verify_signature(manipulated_signature.as_str(), address.as_str()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Signature verification failed");
    }

    #[tokio::test]
    async fn test_signature_manipulation() {
        self::init_settings();
        let (address, signature) = create_signed_message().await;
        let manipulated_signature = format!("9999{}", &signature[4..]);
        let result = verify_signature(manipulated_signature.as_str(), address.as_str()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_address() {
        init_settings();
        let (_, signature) = create_signed_message().await;
        let result = verify_signature(signature.as_str(), "0x123").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Signature verification failed");
    }

    #[tokio::test]
    async fn test_verify_identity_signature_success() {
        init_settings();
        let (address, signature) = create_signed_message().await;
        let result = verify_signature(signature.as_str(), address.as_str()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), address);
    }
}
