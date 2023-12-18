use serde_bytes::ByteBuf;

use crate::utils::{
    delegation::prepare_delegation,
    eth::{recover_eth_address, validate_eth_address, validate_eth_signature},
    siwe::get_siwe_message,
};

pub fn login(signature: &str, address: &str, session_key: ByteBuf) -> Result<ByteBuf, String> {
    validate_eth_signature(signature)?;
    validate_eth_address(address)?;

    let message = get_siwe_message(&address)?;
    let message_string: String = message.clone().into();

    let recovered_address = recover_eth_address(&message_string, signature)?;
    if recovered_address != address {
        return Err(String::from("Signature verification failed"));
    }

    prepare_delegation(address, session_key, &message)
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         login,
//         types::settings::SettingsBuilder,
//         utils::siwe::{add_siwe_message, create_siwe_message},
//         SETTINGS,
//     };
//     use ethers::{
//         signers::{LocalWallet, Signer},
//         utils::to_checksum,
//     };
//     use serde_bytes::ByteBuf;
//     use std::time::Duration;

//     const VALID_ADDRESS: &str = "0xc2cc7160837714a78ff9f9191ec5a1bb15096179";
//     const SESSION_KEY: &[u8] = b"987687687687687687687687686";

//     fn init_settings() {
//         let settings = SettingsBuilder::new("example.com", "http://example.com", "salt")
//             .scheme("https")
//             .statement("Login to the app")
//             .sign_in_expires_in(Duration::from_secs(2).as_nanos() as u64) // Sign in expires in 2 seconds
//             .build()
//             .unwrap();
//         SETTINGS.with(|s| {
//             *s.borrow_mut() = Some(settings);
//         });
//     }

//     // Too short signature
//     #[tokio::test]
//     async fn test_signature_too_short() {
//         init_settings();
//         create_siwe_message(VALID_ADDRESS).unwrap();
//         let invalid_signature = "0";
//         let result = login(invalid_signature, VALID_ADDRESS, ByteBuf::from(SESSION_KEY));
//         assert!(result.is_err());
//         assert_eq!(
//             result.unwrap_err(),
//             "Invalid signature: Must start with '0x' and be 132 characters long"
//         );
//     }

//     #[tokio::test]
//     async fn test_incorrect_signature_format() {
//         init_settings();
//         create_siwe_message(VALID_ADDRESS).unwrap();
//         let invalid_signature = "0xÖÖ809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809800"; // A signature with the correct length but incorrect format
//         let result = login(invalid_signature, VALID_ADDRESS, ByteBuf::from(SESSION_KEY));
//         assert!(result.is_err());
//         // Assert the specific error message or type you expect for an incorrect format
//     }

//     // Too long signature
//     #[tokio::test]
//     async fn test_signature_too_long() {
//         init_settings();
//         create_siwe_message(VALID_ADDRESS).unwrap();
//         let invalid_signature = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
//         let result = login(invalid_signature, VALID_ADDRESS, ByteBuf::from(SESSION_KEY));
//         assert!(result.is_err());
//         assert_eq!(
//             result.unwrap_err(),
//             "Invalid signature: Must start with '0x' and be 132 characters long"
//         );
//     }

//     // Test for hex decoding failure
//     #[tokio::test]
//     async fn test_hex_decoding_failure() {
//         init_settings();
//         create_siwe_message(VALID_ADDRESS).unwrap();
//         let invalid_hex_signature = "0xGMGM000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // Non-hex characters
//         let result = login(
//             invalid_hex_signature,
//             VALID_ADDRESS,
//             ByteBuf::from(SESSION_KEY),
//         );
//         assert!(result.is_err());
//         assert_eq!(
//             result.unwrap_err(),
//             "Invalid signature: Hex decoding failed"
//         );
//     }

//     // Sign in message lives only for 2 seconds
//     #[tokio::test]
//     async fn test_sign_in_message_expired() {
//         init_settings();
//         let wallet = LocalWallet::new(&mut rand::thread_rng());
//         let h160 = wallet.address();
//         let address = to_checksum(&h160, None);
//         let message = create_siwe_message(address.as_str()).unwrap();
//         add_siwe_message(message.clone());
//         let message: String = message.into();
//         let signature = wallet.sign_message(message).await.unwrap().to_string();
//         let result = login(
//             &format!("0x{}", signature.as_str()),
//             address.as_str(),
//             ByteBuf::from(SESSION_KEY),
//         );
//         assert_eq!(result.unwrap_err(), "Signature verification failed");

//         // assert!(result.is_ok());

//         // Wait for 3 seconds
//         tokio::time::sleep(Duration::from_secs(3)).await;

//         let result = login(
//             &format!("0x{}", signature.as_str()),
//             address.as_str(),
//             ByteBuf::from(SESSION_KEY),
//         ); // Attempt to login again
//         assert!(result.is_err());
//         assert_eq!(
//             result.unwrap_err(),
//             "Message not found for the given address"
//         );
//     }

//     // A valid signature but with a different address
//     #[tokio::test]
//     async fn test_recovery_address_mismatch() {
//         init_settings();
//         create_siwe_message(VALID_ADDRESS).unwrap();
//         let wallet = LocalWallet::new(&mut rand::thread_rng());
//         let h160 = wallet.address();
//         let address = to_checksum(&h160, None);
//         let message: String = create_siwe_message(address.as_str()).unwrap().into();
//         let signature = wallet.sign_message(message).await.unwrap().to_string();
//         let result = login(
//             &format!("0x{}", signature.as_str()),
//             VALID_ADDRESS,
//             ByteBuf::from(SESSION_KEY),
//         );
//         assert!(result.is_err());
//         assert_eq!(result.unwrap_err(), "Signature verification failed");
//     }

//     #[tokio::test]
//     async fn test_invalid_recovery_byte() {
//         init_settings();
//         let wallet = LocalWallet::new(&mut rand::thread_rng());
//         let h160 = wallet.address();
//         let address = to_checksum(&h160, None);
//         let message: String = create_siwe_message(address.as_str()).unwrap().into();
//         let signature = wallet.sign_message(message).await.unwrap().to_string();
//         let manipulated_signature = format!("{}0000000000", &signature[..signature.len() - 10]);
//         let result = login(
//             &format!("0x{}", manipulated_signature.as_str()),
//             address.as_str(),
//             ByteBuf::from(SESSION_KEY),
//         );
//         assert!(result.is_err());
//         assert_eq!(result.unwrap_err(), "Signature verification failed");
//     }

//     #[tokio::test]
//     async fn test_signature_manipulation() {
//         init_settings();
//         let wallet = LocalWallet::new(&mut rand::thread_rng());
//         let h160 = wallet.address();
//         let address = to_checksum(&h160, None);
//         let message: String = create_siwe_message(address.as_str()).unwrap().into();
//         let signature = wallet.sign_message(message).await.unwrap().to_string();
//         let manipulated_signature = format!("9999{}", &signature[4..]);
//         let result = login(
//             &format!("0x{}", manipulated_signature.as_str()),
//             address.as_str(),
//             ByteBuf::from(SESSION_KEY),
//         );
//         assert!(result.is_err());
//     }

//     #[tokio::test]
//     async fn test_invalid_address() {
//         init_settings();
//         let wallet = LocalWallet::new(&mut rand::thread_rng());
//         let h160 = wallet.address();
//         let address = to_checksum(&h160, None);
//         let message: String = create_siwe_message(address.as_str()).unwrap().into();
//         let signature = wallet.sign_message(message).await.unwrap().to_string();
//         let result = login(signature.as_str(), "0x123", ByteBuf::from(SESSION_KEY)); // Wrong address
//         assert!(result.is_err());
//         assert_eq!(
//             result.unwrap_err(),
//             "Message not found for the given address"
//         );
//     }

//     #[tokio::test]
//     async fn test_successful_login() {
//         init_settings();
//         let wallet = LocalWallet::new(&mut rand::thread_rng());
//         let h160 = wallet.address();
//         let address = to_checksum(&h160, None);
//         let message: String = create_siwe_message(address.as_str()).unwrap().into();
//         let signature = wallet.sign_message(message).await.unwrap().to_string();
//         let result = login(
//             &format!("0x{}", signature.as_str()),
//             address.as_str(),
//             ByteBuf::from(SESSION_KEY),
//         );
//         assert!(result.is_ok());
//     }

//     #[tokio::test]
//     async fn test_replay_attack() {
//         init_settings();

//         let wallet = LocalWallet::new(&mut rand::thread_rng());
//         let h160 = wallet.address();
//         let address = to_checksum(&h160, None);
//         let message: String = create_siwe_message(address.as_str()).unwrap().into();
//         let signature = wallet.sign_message(message).await.unwrap().to_string();

//         let first_attempt = login(
//             &format!("0x{}", signature.as_str()),
//             address.as_str(),
//             ByteBuf::from(SESSION_KEY),
//         );
//         assert!(first_attempt.is_ok());

//         let second_attempt = login(
//             &format!("0x{}", signature.as_str()),
//             address.as_str(),
//             ByteBuf::from(SESSION_KEY),
//         );
//         assert!(second_attempt.is_err());
//         assert_eq!(
//             second_attempt.unwrap_err(),
//             "Message not found for the given address"
//         );
//     }
// }
