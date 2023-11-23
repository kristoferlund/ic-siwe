use crate::{create_identity_message, utils::eth::recover_address};
use candid::Principal;
use ed25519_consensus::SigningKey;
use k256::sha2::{self, Digest};
use tiny_keccak::{Hasher, Keccak};

pub fn ed25519_public_key_to_der(mut key: Vec<u8>) -> Vec<u8> {
    // The constant is the prefix of the DER encoding of the ASN.1
    // SubjectPublicKeyInfo data structure. It can be read as follows:
    // 0x30 0x2A: Sequence of length 42 bytes
    //   0x30 0x05: Sequence of length 5 bytes
    //     0x06 0x03 0x2B 0x65 0x70: OID of length 3 bytes, 1.3.101.112 (where 43 =
    //              1 * 40 + 3)
    //   0x03 0x21: Bit string of length 33 bytes
    //     0x00 [raw key]: No padding [raw key]
    let mut encoded: Vec<u8> = vec![
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    encoded.append(&mut key);
    encoded
}

pub fn ed25519_public_key_from_der(mut key_der: Vec<u8>) -> Vec<u8> {
    assert!(key_der.len() > 12);
    key_der.drain(0..12);
    key_der
}

pub fn verify_identity_signature(
    signature: &str,
    address: &str,
    principal: Principal,
) -> Result<String, String> {
    // Log the principal for debugging or informational purposes
    ic_cdk::println!("Principal: {:?}", principal);

    // Create an identity message based on the provided address
    let identity_message = create_identity_message(address)?;

    // Recover the address from the signature and the identity message
    let recovered_address = recover_address(identity_message.as_str(), signature)?;
    if recovered_address != address {
        // If the recovered address does not match the provided address, return an error
        return Err("Signature verification failed".to_string());
    }

    // Compute the Keccak-256 hash of the signature
    let mut keccak256_hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signature.as_bytes());
    hasher.finalize(&mut keccak256_hash);

    // Generate a signing key from the Keccak-256 hash
    let signing_key = SigningKey::from(keccak256_hash);

    // Extract the public key from the signing key
    let public_key_bytes = signing_key.verification_key().to_bytes();

    // Convert the public key to DER format
    let public_key_der = ed25519_public_key_to_der(public_key_bytes.to_vec());

    // Compute the SHA-224 hash of the DER-encoded public key. Should be the same
    // as the first 28 bytes of the principal.
    let sha224_hash = sha2::Sha224::new().chain_update(public_key_der).finalize();
    ic_cdk::println!("SHA-224 Hash: {:?}", sha224_hash);

    // Return the original address on successful verification
    Ok(address.to_string())
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{types::settings::SettingsBuilder, SETTINGS};
//     use ethers::{
//         signers::{LocalWallet, Signer},
//         utils::to_checksum,
//     };
//     use std::time::Duration;

//     const VALID_ADDRESS: &str = "0xc2cc7160837714a78ff9f9191ec5a1bb15096179";

//     fn init_settings() {
//         let settings = SettingsBuilder::new("example.com", "http://example.com")
//             .scheme("https")
//             .statement("Login to the app")
//             .sign_in_expires_in(Duration::from_secs(2).as_nanos() as u64) // Sign in expires in 2 seconds
//             .build()
//             .unwrap();
//         SETTINGS.with(|s| {
//             *s.borrow_mut() = Some(settings);
//         });
//     }

//     async fn create_signed_message() -> (String, String) {
//         let wallet = LocalWallet::new(&mut rand::thread_rng());
//         let h160 = wallet.address();
//         let address = to_checksum(&h160, None);
//         let message: String = create_identity_message(address.as_str()).unwrap().into();
//         let signature = wallet.sign_message(message.clone()).await.unwrap();
//         (address, signature.to_string())
//     }

//     async fn verify_signature(signature: &str, address: &str) -> Result<String, String> {
//         init_settings();
//         verify_identity_signature(signature, address)
//     }
//     // Too short signature
//     #[tokio::test]
//     async fn test_signature_too_short() {
//         let result = verify_signature("0", VALID_ADDRESS).await;
//         assert!(result.is_err());
//         assert_eq!(result.unwrap_err(), "Invalid signature length");
//     }

//     #[tokio::test]
//     async fn test_incorrect_signature_format() {
//         init_settings();
//         let invalid_signature = "0xÖÖ809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809800"; // A signature with the correct length but incorrect format
//         let result = verify_identity_signature(invalid_signature, VALID_ADDRESS);
//         assert!(result.is_err());
//     }

//     // Too long signature
//     #[tokio::test]
//     async fn test_signature_too_long() {
//         let long_signature = "0".repeat(135);
//         let result = verify_signature(long_signature.as_str(), VALID_ADDRESS).await;
//         assert!(result.is_err());
//         assert_eq!(result.unwrap_err(), "Invalid signature length");
//     }

//     // Test for hex decoding failure
//     #[tokio::test]
//     async fn test_hex_decoding_failure() {
//         init_settings();
//         let invalid_hex_signature = "GMGM000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // Non-hex characters
//         let result = verify_identity_signature(invalid_hex_signature, VALID_ADDRESS);
//         assert!(result.is_err());
//         assert_eq!(
//             result.unwrap_err(),
//             "Failed to decode signature due to invalid format"
//         );
//     }

//     // A valid signature but with a different address
//     #[tokio::test]
//     async fn test_recovery_address_mismatch() {
//         init_settings();
//         let (_, signature) = create_signed_message().await;
//         let result = verify_signature(signature.as_str(), VALID_ADDRESS).await;
//         assert!(result.is_err());
//         assert_eq!(result.unwrap_err(), "Signature verification failed");
//     }

//     #[tokio::test]
//     async fn test_invalid_recovery_byte() {
//         init_settings();
//         let (address, signature) = create_signed_message().await;
//         let manipulated_signature = format!("{}0000000000", &signature[..signature.len() - 10]);
//         let result = verify_signature(manipulated_signature.as_str(), address.as_str()).await;
//         assert!(result.is_err());
//         assert_eq!(result.unwrap_err(), "Invalid recovery byte");
//     }

//     #[tokio::test]
//     async fn test_signature_manipulation() {
//         init_settings();
//         let (address, signature) = create_signed_message().await;
//         let manipulated_signature = format!("9999{}", &signature[4..]);
//         let result = verify_signature(manipulated_signature.as_str(), address.as_str()).await;
//         assert!(result.is_err());
//     }

//     #[tokio::test]
//     async fn test_invalid_address() {
//         init_settings();
//         let (_, signature) = create_signed_message().await;
//         let result = verify_signature(signature.as_str(), "0x123").await;
//         assert!(result.is_err());
//         assert_eq!(result.unwrap_err(), "Signature verification failed");
//     }

//     #[tokio::test]
//     async fn test_verify_identity_signature_success() {
//         init_settings();
//         let (address, signature) = create_signed_message().await;
//         let result = verify_signature(signature.as_str(), address.as_str()).await;
//         assert!(result.is_ok());
//         assert_eq!(result.unwrap(), address);
//     }
// }
