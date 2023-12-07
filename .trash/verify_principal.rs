use crate::utils::ed25519::ed25519_public_key_to_der;
use candid::Principal;
use ed25519_dalek::SigningKey;
use k256::sha2::{self, Digest};
use tiny_keccak::{Hasher, Keccak};

pub enum VerifyPrincipalError {
    PrincipalTooShort,
    VerificationFailed,
    SigningKeyError,
    InvalidSignatureLength,
}

impl std::fmt::Display for VerifyPrincipalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VerifyPrincipalError::PrincipalTooShort => write!(f, "Principal is too short"),
            VerifyPrincipalError::VerificationFailed => write!(f, "Principal verification failed"),
            VerifyPrincipalError::SigningKeyError => {
                write!(f, "Error generating signing key from hash")
            }
            VerifyPrincipalError::InvalidSignatureLength => write!(f, "Invalid signature length"),
        }
    }
}

impl From<VerifyPrincipalError> for String {
    fn from(error: VerifyPrincipalError) -> Self {
        error.to_string()
    }
}

pub fn verify_principal(signature: &str, principal: Principal) -> Result<(), VerifyPrincipalError> {
    // Verify that the signature has the expected length (130 characters)
    // Ed25519 signatures are 64 bytes long, hence 128 hex characters; add 2 for prefix '0x'
    // if signature.len() != 65 * 2 {
    //     return Err(VerifyPrincipalError::InvalidSignatureLength);
    // }

    // Compute the Keccak-256 hash of the signature
    let mut keccak256_hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signature.as_bytes());
    hasher.finalize(&mut keccak256_hash);

    // Generate a signing key from the Keccak-256 hash
    let signing_key = SigningKey::from_bytes(&keccak256_hash);

    // Extract the public key from the signing key
    let public_key_bytes = signing_key.verifying_key().to_bytes();

    // Convert the public key to DER format
    let public_key_der = ed25519_public_key_to_der(public_key_bytes.to_vec());

    // Compute the SHA-224 hash of the DER-encoded public key. Should be the same
    // as the first 28 bytes of the principal.
    let sha224_hash = sha2::Sha224::new().chain_update(public_key_der).finalize();

    // Compare the SHA-224 hash to the first 28 bytes of the principal
    let principal_bytes = principal.as_slice();
    if principal_bytes.len() < 28 {
        return Err(VerifyPrincipalError::PrincipalTooShort);
    }

    if sha224_hash[..] == principal_bytes[..28] {
        Ok(())
    } else {
        Err(VerifyPrincipalError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_identity_message, types::settings::SettingsBuilder, SETTINGS};
    use ethers::{
        signers::{LocalWallet, Signer},
        utils::to_checksum,
    };
    use std::time::Duration;

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

    async fn create_principal(signature: &str) -> Result<Principal, String> {
        // Compute the Keccak-256 hash of the signature
        let mut keccak256_hash = [0; 32];
        let mut hasher = Keccak::v256();
        hasher.update(signature.as_bytes());
        hasher.finalize(&mut keccak256_hash);

        // Generate a signing key from the Keccak-256 hash
        let siging_key = SigningKey::from_bytes(&keccak256_hash);

        // Extract the public key from the signing key
        let public_key_bytes = siging_key.verifying_key().to_bytes();

        // Convert the public key to DER format
        let public_key_der = ed25519_public_key_to_der(public_key_bytes.to_vec());

        // Compute the SHA-224 hash of the DER-encoded public key.
        let sha224_hash = sha2::Sha224::new().chain_update(public_key_der).finalize();

        // Create a principal from the SHA-224 hash
        let principal = Principal::from_slice(&sha224_hash);

        Ok(principal)
    }

    // Too short signature
    #[tokio::test]
    async fn test_signature_too_short() {
        init_settings();
        let (_, signature) = create_signed_message().await;
        let principal = create_principal(&signature).await.unwrap();
        let result = verify_principal("0", principal);
        assert!(result.is_err());
        let err: String = result.unwrap_err().into();
        assert_eq!(err, "Invalid signature length");
    }

    // Too long signature
    #[tokio::test]
    async fn test_signature_too_long() {
        init_settings();
        let long_signature = "0".repeat(135);
        let principal = create_principal(&long_signature).await.unwrap();
        let result = verify_principal(long_signature.as_str(), principal);
        assert!(result.is_err());
        let err: String = result.unwrap_err().into();
        assert_eq!(err, "Invalid signature length");
    }

    // Success
    #[tokio::test]
    async fn test_success() {
        init_settings();
        let (_, signature) = create_signed_message().await;
        let principal = create_principal(&signature).await.unwrap();
        let result = verify_principal(&signature, principal);
        assert!(result.is_ok());
    }
}
