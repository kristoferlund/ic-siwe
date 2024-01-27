use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use std::fmt;
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug)]
pub enum EthError {
    AddressFormatError(String),
    DecodingError(hex::FromHexError),
    InvalidSignature,
    InvalidRecoveryId,
    PublicKeyRecoveryFailure,
    Eip55Error(String),
}

impl From<hex::FromHexError> for EthError {
    fn from(err: hex::FromHexError) -> Self {
        EthError::DecodingError(err)
    }
}

impl fmt::Display for EthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EthError::AddressFormatError(e) => write!(f, "Format error: {}", e),
            EthError::DecodingError(e) => write!(f, "Decoding error: {}", e),
            EthError::InvalidSignature => write!(f, "Invalid signature"),
            EthError::InvalidRecoveryId => write!(f, "Invalid recovery ID"),
            EthError::PublicKeyRecoveryFailure => {
                write!(f, "Public key recovery failure")
            }
            EthError::Eip55Error(e) => write!(f, "EIP-55 error: {}", e),
        }
    }
}

impl From<EthError> for String {
    fn from(error: EthError) -> Self {
        error.to_string()
    }
}
/// Recovers an Ethereum address from a given message and signature.
///
/// # Parameters
///
/// * `message` - The message that was signed.
/// * `signature` - The hex-encoded signature.
///
/// # Returns
///
/// The recovered Ethereum address if successful, or an error.
pub fn recover_eth_address(message: &str, signature: &str) -> Result<String, EthError> {
    let message_hash = eip191_hash(message);
    let signature_bytes = decode_signature(signature)?;

    let recovery_id =
        RecoveryId::try_from(signature_bytes[64] % 27).map_err(|_| EthError::InvalidRecoveryId)?;

    let signature =
        Signature::from_slice(&signature_bytes[..64]).map_err(|_| EthError::InvalidSignature)?;

    let verifying_key = VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)
        .map_err(|_| EthError::PublicKeyRecoveryFailure)?;

    let address = derive_eth_address_from_public_key(&verifying_key)?;

    Ok(address)
}

/// Hashes a message using the EIP-191 standard. See [EIP-191 spec](https://eips.ethereum.org/EIPS/eip-191) for
/// more information.
///
/// # Parameters
///
/// * `message` - The message to hash.
///
/// # Returns
///
/// A 32-byte array containing the hash.
pub fn eip191_hash(message: &str) -> [u8; 32] {
    let mut keccak256 = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&eip191_bytes(message));
    hasher.finalize(&mut keccak256);

    keccak256
}

/// Formats a message according to the EIP-191 standard. See [EIP-191 spec](https://eips.ethereum.org/EIPS/eip-191) for
/// for more information.
///
/// # Parameters
///
/// * `message` - The message to format.
///
/// # Returns
///
/// A vector of bytes containing the formatted message.
pub fn eip191_bytes(message: &str) -> Vec<u8> {
    format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message).into_bytes()
}

/// Decodes a hex-encoded Ethereum signature.
///
/// # Parameters
///
/// * `signature` - The hex-encoded signature. The signature must be prefixed with '0x' and be 132
///  characters long.
///
/// # Returns
///
/// A vector of bytes containing the decoded signature if successful, or an error.
pub fn decode_signature(signature: &str) -> Result<Vec<u8>, EthError> {
    validate_eth_signature(signature).map_err(|_| EthError::InvalidSignature)?;

    let signature = if signature.starts_with("0x") {
        signature.strip_prefix("0x").unwrap()
    } else {
        signature
    };

    hex::decode(signature).map_err(EthError::DecodingError)
}

/// Converts an Ethereum address to bytes by stripping the '0x' prefix and decoding the hexadecimal
/// string.
///
/// # Parameters
///
/// * `address` - The Ethereum address to convert.
///
/// # Returns
///
/// A vector of bytes containing the decoded address if successful, or an error.
pub fn eth_address_to_bytes(address: &str) -> Result<Vec<u8>, EthError> {
    // Strip the '0x' prefix if present
    let addr_trimmed = if address.starts_with("0x") {
        address.strip_prefix("0x").unwrap()
    } else {
        address
    };

    // Decode the hexadecimal string to bytes
    hex::decode(addr_trimmed).map_err(EthError::DecodingError)
}

/// Converts a byte array to an Ethereum address by encoding the bytes to a hexadecimal string and
/// adding the '0x' prefix.
///
/// # Parameters
///
/// * `bytes` - The byte array to convert. Must be 20 bytes long.
pub fn bytes_to_eth_address(bytes: &[u8; 20]) -> String {
    // Encode the bytes to a hexadecimal string
    let addr = hex::encode(bytes);

    // Add the '0x' prefix
    format!("0x{}", addr)
}

/// Derives an Ethereum address from an ECDSA public key.
///
/// # Parameters
///
/// * `key` - The ECDSA public key to derive the address from.
///
/// # Returns
///
/// The derived Ethereum address if successful, or an error.
pub fn derive_eth_address_from_public_key(key: &VerifyingKey) -> Result<String, EthError> {
    let mut keccak256 = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&key.to_encoded_point(false).as_bytes()[1..]);
    hasher.finalize(&mut keccak256);

    let keccak256_hex = hex::encode(keccak256);
    convert_to_eip55(&keccak256_hex[24..])
}

/// Converts an Ethereum address to EIP-55 format. See [EIP-55 spec](https://eips.ethereum.org/EIPS/eip-55) for
/// more information.
///
/// # Parameters
///
/// * `address` - The Ethereum address to convert.
///
/// # Returns
///
/// The EIP-55-compliant Ethereum address if successful, or an error.
pub fn convert_to_eip55(address: &str) -> Result<String, EthError> {
    let address_trimmed = if address.starts_with("0x") {
        address.strip_prefix("0x").unwrap()
    } else {
        address
    };

    let address_lowercase = address_trimmed.to_lowercase();

    // Compute Keccak-256 hash of the lowercase address
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(address_lowercase.as_bytes());
    hasher.finalize(&mut hash);

    // Iterate over each character in the original address
    let checksummed_addr = address_trimmed
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
        .collect::<Result<String, String>>()
        .map_err(EthError::Eip55Error)?; // Convert to error type

    Ok(format!("0x{}", checksummed_addr))
}

/// Validates an Ethereum address by checking its length, hex encoding, and EIP-55 encoding. A valid
/// address must be prefixed with '0x', be 42 characters long, and be EIP-55 encoded.
pub fn validate_eth_address(address: &str) -> Result<(), EthError> {
    if !address.starts_with("0x") || address.len() != 42 {
        return Err(EthError::AddressFormatError(String::from(
            "Must start with '0x' and be 42 characters long",
        )));
    }

    hex::decode(&address[2..]).map_err(EthError::DecodingError)?;

    if address != convert_to_eip55(address).unwrap() {
        return Err(EthError::Eip55Error(String::from("Not EIP-55 encoded")));
    }

    Ok(())
}

/// Validates an Ethereum signature by checking its length and hex encoding. A valid signature must
/// be prefixed with '0x' and be 132 characters long.
pub fn validate_eth_signature(signature: &str) -> Result<(), EthError> {
    if !signature.starts_with("0x") || signature.len() != 132 {
        return Err(EthError::AddressFormatError(String::from(
            "Must start with '0x' and be 132 characters long",
        )));
    }

    hex::decode(&signature[2..]).map_err(EthError::DecodingError)?;
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
        let err_msg: String = result.unwrap_err().into();
        assert_eq!(err_msg, "EIP-55 error: Not EIP-55 encoded");
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
