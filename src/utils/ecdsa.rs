use std::fmt;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};

/// An error type for signature recovery.
#[derive(Debug)]
pub enum SignatureRecoveryError {
    DecodingError(hex::FromHexError),
    InvalidSignature,
    InvalidSignatureLength,
    InvalidRecoveryId,
    PublicKeyRecoveryFailure,
    Eip191HashError,
    Eip191BytesError,
}

impl From<hex::FromHexError> for SignatureRecoveryError {
    fn from(err: hex::FromHexError) -> Self {
        SignatureRecoveryError::DecodingError(err)
    }
}

impl fmt::Display for SignatureRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureRecoveryError::DecodingError(e) => write!(f, "Decoding error: {}", e),
            SignatureRecoveryError::InvalidSignature => write!(f, "Invalid signature"),
            SignatureRecoveryError::InvalidSignatureLength => {
                write!(f, "Invalid signature length")
            }
            SignatureRecoveryError::InvalidRecoveryId => write!(f, "Invalid recovery ID"),
            SignatureRecoveryError::PublicKeyRecoveryFailure => {
                write!(f, "Public key recovery failure")
            }
            SignatureRecoveryError::Eip191HashError => write!(f, "EIP-191 hash error"),
            SignatureRecoveryError::Eip191BytesError => write!(f, "EIP-191 bytes error"),
        }
    }
}

impl From<SignatureRecoveryError> for String {
    fn from(error: SignatureRecoveryError) -> Self {
        error.to_string()
    }
}
/// Recovers an Ethereum address from a given message and signature.
///
/// # Arguments
///
/// * `message` - The message that was signed.
/// * `signature` - The hex-encoded signature.
///
/// # Returns
///
/// The recovered Ethereum address if successful, or an error.
pub(crate) fn recover_address(
    message: &str,
    signature: &str,
) -> Result<String, SignatureRecoveryError> {
    let message_hash = eip191_hash(message)?;
    let signature_bytes = decode_signature(signature)?;

    let recovery_id = RecoveryId::try_from(signature_bytes[64] % 27)
        .map_err(|_| SignatureRecoveryError::InvalidRecoveryId)?;

    let signature = Signature::from_slice(&signature_bytes[..64])
        .map_err(|_| SignatureRecoveryError::InvalidSignature)?;

    let verifying_key = VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)
        .map_err(|_| SignatureRecoveryError::PublicKeyRecoveryFailure)?;

    let address = derive_ethereum_address_from_public_key(&verifying_key)?;
    Ok(address)
}

/// Decodes a hex-encoded signature.
fn decode_signature(signature: &str) -> Result<Vec<u8>, SignatureRecoveryError> {
    let signature = if signature.starts_with("0x") {
        &signature[2..]
    } else {
        signature
    };

    if signature.len() != 65 * 2 {
        return Err(SignatureRecoveryError::InvalidSignatureLength);
    }

    hex::decode(signature)
        .map_err(|err| SignatureRecoveryError::DecodingError(err))
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|_| SignatureRecoveryError::InvalidSignatureLength)
        })
}

/// Hashes a message using the EIP-191 standard.
fn eip191_hash(message: &str) -> Result<[u8; 32], SignatureRecoveryError> {
    let mut keccak256 = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(eip191_bytes(message)?.as_slice());
    hasher.finalize(&mut keccak256);

    Ok(keccak256)
}

/// Formats a message according to the EIP-191 standard.
fn eip191_bytes(message: &str) -> Result<Vec<u8>, SignatureRecoveryError> {
    Ok(format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message).into_bytes())
}

/// Derives an Ethereum address from a public key.
fn derive_ethereum_address_from_public_key(
    key: &VerifyingKey,
) -> Result<String, SignatureRecoveryError> {
    let mut keccak256 = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&key.to_encoded_point(false).as_bytes()[1..]);
    hasher.finalize(&mut keccak256);

    let keccak256_hex = hex::encode(keccak256);
    Ok(convert_to_eip55(&keccak256_hex[24..]))
}

/// Converts an Ethereum address into EIP-55 format.
fn convert_to_eip55(addr: &str) -> String {
    let mut keccak256 = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(addr.as_bytes());
    hasher.finalize(&mut keccak256);

    "0x".chars()
        .chain(addr.chars().enumerate().map(|(i, c)| {
            match (c, keccak256[i >> 1] & if i % 2 == 0 { 128 } else { 8 } != 0) {
                ('a'..='f' | 'A'..='F', true) => c.to_ascii_uppercase(),
                _ => c.to_ascii_lowercase(),
            }
        }))
        .collect()
}
