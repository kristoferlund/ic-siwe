use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use std::fmt;
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
pub fn recover_eth_address(
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

    let address = derive_eth_address_from_public_key(&verifying_key)?;

    Ok(address)
}

pub fn eth_address_to_bytes(addr: &str) -> Result<Vec<u8>, String> {
    // Strip the '0x' prefix if present
    let addr_trimmed = if addr.starts_with("0x") {
        addr.strip_prefix("0x").unwrap()
    } else {
        addr
    };

    // Decode the hexadecimal string to bytes
    hex::decode(addr_trimmed)
        .map_err(|_| String::from("Invalid Ethereum address: Hex decoding failed"))
}

pub fn bytes_to_eth_address(bytes: &[u8]) -> String {
    // Encode the bytes to a hexadecimal string
    let addr = hex::encode(bytes);

    // Add the '0x' prefix
    format!("0x{}", addr)
}

/// Decodes a hex-encoded signature.
pub fn decode_signature(signature: &str) -> Result<Vec<u8>, SignatureRecoveryError> {
    validate_eth_signature(signature).map_err(|_| SignatureRecoveryError::InvalidSignature)?;

    let signature = if signature.starts_with("0x") {
        signature.strip_prefix("0x").unwrap()
    } else {
        signature
    };

    hex::decode(signature).map_err(SignatureRecoveryError::DecodingError)
}

/// Hashes a message using the EIP-191 standard.
pub fn eip191_hash(message: &str) -> Result<[u8; 32], SignatureRecoveryError> {
    let mut keccak256 = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&eip191_bytes(message)?);
    hasher.finalize(&mut keccak256);

    Ok(keccak256)
}

/// Formats a message according to the EIP-191 standard.
pub fn eip191_bytes(message: &str) -> Result<Vec<u8>, SignatureRecoveryError> {
    Ok(format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message).into_bytes())
}

/// Derives an Ethereum address from a public key.
pub fn derive_eth_address_from_public_key(
    key: &VerifyingKey,
) -> Result<String, SignatureRecoveryError> {
    let mut keccak256 = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&key.to_encoded_point(false).as_bytes()[1..]);
    hasher.finalize(&mut keccak256);

    let keccak256_hex = hex::encode(keccak256);
    Ok(convert_to_eip55(&keccak256_hex[24..]).unwrap())
}

/// Converts an Ethereum address to EIP-55 format.
pub fn convert_to_eip55(addr: &str) -> Result<String, String> {
    let addr_trimmed = if addr.starts_with("0x") {
        addr.strip_prefix("0x").unwrap()
    } else {
        addr
    };

    let addr_lowercase = addr_trimmed.to_lowercase();

    // Compute Keccak-256 hash of the lowercase address
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(addr_lowercase.as_bytes());
    hasher.finalize(&mut hash);

    // Iterate over each character in the original address
    let checksummed_addr = addr_trimmed
        .char_indices()
        .map(|(i, c)| {
            let result = match c {
                '0'..='9' => c.to_string(), // Keep digits as is
                'a'..='f' | 'A'..='F' => {
                    // Extract the corresponding nibble from the hash
                    let hash_nibble = if i % 2 == 0 {
                        (hash[i / 2] >> 4) & 0x0f
                    } else {
                        hash[i / 2] & 0x0f
                    };

                    // Uppercase if the nibble is 8 or more
                    if hash_nibble >= 8 {
                        c.to_ascii_uppercase().to_string()
                    } else {
                        c.to_ascii_lowercase().to_string()
                    }
                }
                _ => {
                    return Err(format!(
                        "Unrecognized hex character '{}' at position {}",
                        c, i
                    ));
                }
            };
            Ok(result)
        })
        .collect::<Result<String, String>>()?;

    Ok(format!("0x{}", checksummed_addr))
}

/// Validates an Ethereum address by checking its length, hex encoding, and EIP-55 encoding.
pub fn validate_eth_address(address: &str) -> Result<(), String> {
    if !address.starts_with("0x") || address.len() != 42 {
        return Err(String::from(
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long",
        ));
    }

    hex::decode(&address[2..]).map_err(|_| "Invalid Ethereum address: Hex decoding failed")?;

    if address != convert_to_eip55(address).unwrap() {
        return Err(String::from("Invalid Ethereum address: Not EIP-55 encoded"));
    }

    Ok(())
}

/// Validates an Ethereum signature by checking its length and hex encoding.
pub fn validate_eth_signature(signature: &str) -> Result<(), String> {
    if !signature.starts_with("0x") || signature.len() != 132 {
        return Err(String::from(
            "Invalid signature: Must start with '0x' and be 132 characters long",
        ));
    }

    hex::decode(&signature[2..]).map_err(|_| "Invalid signature: Hex decoding failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::eth::{convert_to_eip55, validate_eth_address};

    #[test]
    fn test_eip55_invalid_address() {
        let invalid_address = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let result = validate_eth_address(invalid_address);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Not EIP-55 encoded"
        );
    }

    #[test]
    fn test_eip55_valid_non_eip55_address() {
        let valid_address = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359";
        let valid_address_eip55 = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
        let result = convert_to_eip55(valid_address);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_address_eip55);
    }

    #[test]
    fn test_eip55_valid_eip55_address() {
        let valid_address_eip55 = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
        let result = convert_to_eip55(valid_address_eip55);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_address_eip55);
    }
}
