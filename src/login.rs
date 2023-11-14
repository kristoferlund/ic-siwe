use crate::{
    types::{settings::get_settings, siwe_message::SiweMessage},
    utils::time::get_current_time,
    SIGN_IN_MESSAGES,
};
use siwe::{Message, VerificationOpts};
use time::OffsetDateTime;

/// Attempts to log in using the provided signature and address.
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
pub async fn login(signature: String, address: String) -> Result<String, String> {
    prune_expired_messages();

    let signature_bytes = decode_signature(&signature)?;
    let message = get_siwe_message(&address)?;

    verify_message(&message, &signature_bytes).await?;

    Ok(address)
}

/// Removes SIWE messages that have exceeded their time to live.
fn prune_expired_messages() {
    let current_time = get_current_time();

    SIGN_IN_MESSAGES.with_borrow_mut(|map| {
        map.retain(|_, message| message.expiration_time > current_time);
    });
}

/// Decodes the signature string. Skips the "0x" prefix.
fn decode_signature(mut signature: &str) -> Result<[u8; 65], String> {
    signature = signature.strip_prefix("0x").unwrap_or(signature);
    if signature.len() != 65 * 2 {
        return Err(String::from("Invalid signature length"));
    }

    hex::decode(&signature)
        .map_err(|_| String::from("Failed to decode signature due to invalid format"))
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|_| String::from("Invalid signature length"))
        })
}

/// Fetches the SIWE message associated with the provided address.
fn get_siwe_message(address: &str) -> Result<SiweMessage, String> {
    SIGN_IN_MESSAGES
        .with_borrow(|map| map.get(address.as_bytes()).cloned())
        .ok_or_else(|| String::from("Message not found for the given address"))
}

/// Verifies the SIWE message using the given signature and settings.
async fn verify_message(siwe_message: &SiweMessage, signature: &[u8; 65]) -> Result<(), String> {
    let message: Message = siwe_message
        .to_erc_4361()
        .parse()
        .map_err(|err| format!("Failed to parse SIWE message: {}", err))?;

    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(siwe_message.issued_at as i128)
        .map_err(|_| "Invalid timestamp in the SIWE message".to_string())?;

    let settings = get_settings()?;

    let verification_opts = VerificationOpts {
        domain: Some(
            settings
                .domain
                .parse()
                .map_err(|_| "Failed to parse the domain from settings".to_string())?,
        ),
        nonce: Some(message.nonce.clone()), // If nonce is not used elsewhere, no need to clone
        timestamp: Some(timestamp),
        ..Default::default() // Ensure this is the intended behavior
    };

    message
        .verify(signature, &verification_opts)
        .await
        .map_err(|e| format!("SIWE message verification error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_message, types::settings::SettingsBuilder, SETTINGS};
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
        let invalid_signature = "0";
        let result = login(invalid_signature.to_string(), VALID_ADDRESS.to_string()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid signature length");
    }

    // Too long signature
    #[tokio::test]
    async fn test_signature_too_long() {
        init_settings();
        let invalid_signature = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let result = login(invalid_signature.to_string(), VALID_ADDRESS.to_string()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid signature length");
    }

    // Test for hex decoding failure
    #[tokio::test]
    async fn test_hex_decoding_failure() {
        init_settings();
        let invalid_hex_signature = "GMGM000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // Non-hex characters
        let result = login(invalid_hex_signature.to_string(), VALID_ADDRESS.to_string()).await;
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
        let message = create_message(address.clone()).unwrap().to_erc_4361();
        println!("{:?}", message);
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let result = login(signature.clone(), address.clone()).await;
        assert!(result.is_ok());

        // Wait for 3 seconds
        tokio::time::sleep(Duration::from_secs(3)).await;

        let result = login(signature, address).await; // Attempt to login again
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Message not found for the given address"
        );
    }

    #[tokio::test]
    async fn test_invalid_address() {
        init_settings();
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        let message = create_message(address.clone()).unwrap().to_erc_4361();
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let result = login(signature, String::from("0x123")).await; // Wrong address
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
        let message = create_message(address.clone()).unwrap().to_erc_4361();
        let signature = wallet.sign_message(message).await.unwrap().to_string();
        let result = login(signature, address).await;
        assert!(result.is_ok());
    }
}
