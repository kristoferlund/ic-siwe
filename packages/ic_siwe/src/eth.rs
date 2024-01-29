use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use std::fmt;
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug)]
pub enum EthError {
    AddressFormatError(String),
    DecodingError(hex::FromHexError),
    SignatureFormatError(String),
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
            EthError::AddressFormatError(e) => write!(f, "Address format error: {}", e),
            EthError::DecodingError(e) => write!(f, "Decoding error: {}", e),
            EthError::SignatureFormatError(e) => write!(f, "Signature format error: {}", e),
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

/// Represents an Ethereum address with validation.
///
/// This struct ensures that the contained Ethereum address string is valid according to Ethereum standards.
/// It checks for correct length, hex encoding, and EIP-55 encoding.
#[derive(Debug)]
pub struct EthAddress(String);

impl EthAddress {
    /// Creates a new `EthAddress` after validating the Ethereum address format and encoding.
    ///
    /// The address must start with '0x', be 42 characters long, and comply with EIP-55 encoding.
    ///
    /// # Arguments
    /// * `address` - A string slice representing the Ethereum address.
    pub fn new(address: &str) -> Result<EthAddress, EthError> {
        if !address.starts_with("0x") || address.len() != 42 {
            return Err(EthError::AddressFormatError(String::from(
                "Must start with '0x' and be 42 characters long",
            )));
        }

        hex::decode(&address[2..]).map_err(EthError::DecodingError)?;

        if address != convert_to_eip55(address).unwrap() {
            return Err(EthError::Eip55Error(String::from("Not EIP-55 encoded")));
        }

        Ok(EthAddress(address.to_owned()))
    }

    /// Returns a string slice of the Ethereum address.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts the Ethereum address into a byte vector.
    pub fn as_bytes(&self) -> Vec<u8> {
        let address = self.0.strip_prefix("0x").unwrap();
        hex::decode(address).unwrap()
    }

    /// Converts the Ethereum address into a byte array.
    pub fn as_byte_array(&self) -> [u8; 20] {
        let address = self.0.strip_prefix("0x").unwrap();
        let bytes = hex::decode(address).unwrap();
        let mut array = [0; 20];
        array.copy_from_slice(&bytes);
        array
    }
}

/// Represents an Ethereum signature with validation.
///
/// This struct ensures that the contained Ethereum signature string is valid.
/// It checks for correct length and hex encoding.
#[derive(Debug)]
pub struct EthSignature(String);

impl EthSignature {
    /// Creates a new `EthSignature` after validating the Ethereum signature format.
    ///
    /// The signature must start with '0x' and be 132 characters long.
    ///
    /// # Arguments
    /// * `signature` - A string slice representing the Ethereum signature.
    pub fn new(signature: &str) -> Result<EthSignature, EthError> {
        if !signature.starts_with("0x") || signature.len() != 132 {
            return Err(EthError::SignatureFormatError(String::from(
                "Must start with '0x' and be 132 characters long",
            )));
        }

        hex::decode(&signature[2..]).map_err(EthError::DecodingError)?;
        Ok(EthSignature(signature.to_owned()))
    }

    /// Returns a string slice of the Ethereum signature.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts the Ethereum signature into a byte vector.
    pub fn as_bytes(&self) -> Vec<u8> {
        let signature = self.0.strip_prefix("0x").unwrap();
        hex::decode(signature).unwrap()
    }

    /// Converts the Ethereum signature into a byte array.
    pub fn as_byte_array(&self) -> [u8; 65] {
        let signature = self.0.strip_prefix("0x").unwrap();
        let bytes = hex::decode(signature).unwrap();
        let mut array = [0; 65];
        array.copy_from_slice(&bytes);
        array
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
pub fn recover_eth_address(message: &str, signature: &EthSignature) -> Result<String, EthError> {
    let message_hash = eip191_hash(message);
    let signature_bytes = signature.as_bytes();

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

#[cfg(test)]
mod eth_address {
    use crate::eth::EthAddress;

    #[test]
    fn test_eth_address_invalid_address() {
        let invalid_address = "0xG".to_owned() + &"1".repeat(39); // A mock invalid Ethereum address
        let result = EthAddress::new(invalid_address.as_str());
        assert!(result.is_err());
        let err_msg: String = result.unwrap_err().into();
        assert_eq!(
            err_msg,
            "Decoding error: Invalid character 'G' at position 0"
        );
    }

    #[test]
    fn test_eth_address_invalid_hex_encoding() {
        let invalid_address = "0x".to_owned() + &"G".repeat(40); // Invalid hex
        let result = EthAddress::new(invalid_address.as_str());
        assert!(result.is_err());
        let err_msg: String = result.unwrap_err().into();
        assert_eq!(
            err_msg,
            "Decoding error: Invalid character 'G' at position 0"
        );
    }

    #[test]
    fn test_eth_address_too_short() {
        let invalid_address = "0x".to_owned() + &"1".repeat(39); // Too short
        let result = EthAddress::new(invalid_address.as_str());
        assert!(result.is_err());
        let err_msg: String = result.unwrap_err().into();
        assert_eq!(
            err_msg,
            "Address format error: Must start with '0x' and be 42 characters long"
        );
    }

    #[test]
    fn test_eth_address_too_long() {
        let invalid_address = "0x".to_owned() + &"1".repeat(41); // Too long
        let result = EthAddress::new(invalid_address.as_str());
        assert!(result.is_err());
        let err_msg: String = result.unwrap_err().into();
        assert_eq!(
            err_msg,
            "Address format error: Must start with '0x' and be 42 characters long"
        );
    }
    #[test]
    fn test_eth_address_invalid_eip55() {
        let invalid_address = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let result = EthAddress::new(invalid_address);
        assert!(result.is_err());
        let err_msg: String = result.unwrap_err().into();
        assert_eq!(err_msg, "EIP-55 error: Not EIP-55 encoded");
    }
}

#[cfg(test)]
mod eth_signature {
    use crate::eth::EthSignature;

    // Utility function to generate a valid Ethereum signature for testing
    fn generate_valid_signature() -> String {
        "0x".to_owned() + &"1".repeat(130) // A mock valid Ethereum signature
    }

    #[test]
    fn test_eth_signature_new_valid() {
        let valid_signature = generate_valid_signature();
        let result = EthSignature::new(&valid_signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_eth_signature_new_invalid_format() {
        let invalid_signature = "0x1".to_owned(); // Incorrect format
        let result = EthSignature::new(&invalid_signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_eth_signature_new_invalid_length() {
        let invalid_signature = "0x".to_owned() + &"1".repeat(131); // Incorrect length
        let result = EthSignature::new(&invalid_signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_eth_signature_as_bytes() {
        let valid_signature = generate_valid_signature();
        let eth_signature = EthSignature::new(&valid_signature).unwrap();
        let bytes = eth_signature.as_bytes();
        assert_eq!(bytes.len(), 65);
    }

    #[test]
    fn test_eth_signature_as_byte_array() {
        let valid_signature = generate_valid_signature();
        let eth_signature = EthSignature::new(&valid_signature).unwrap();
        let byte_array = eth_signature.as_byte_array();
        assert_eq!(byte_array.len(), 65);
    }

    // Add more tests to cover different scenarios and edge cases
}

#[cfg(test)]
mod recover_eth_address {
    use ethers::{
        signers::{LocalWallet, Signer},
        utils::{hash_message, to_checksum},
    };

    use crate::eth::{recover_eth_address, EthSignature};

    pub fn create_wallet() -> (ethers::signers::LocalWallet, String) {
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let h160 = wallet.address();
        let address = to_checksum(&h160, None);
        (wallet, address)
    }

    #[test]
    fn test_recover_eth_address() {
        let (wallet, address) = create_wallet();
        let message = "It's me, Marlene, do you miss me?!";
        let hash = hash_message(message.as_bytes());
        let signature = wallet.sign_hash(hash).unwrap().to_string();
        let signature = format!("0x{}", signature.as_str());
        let recovered_address =
            recover_eth_address(message, &EthSignature::new(&signature).unwrap()).unwrap();
        assert_eq!(address, recovered_address);
    }

    #[test]
    fn test_recover_eth_address_with_invalid_signature() {
        let (wallet, _) = create_wallet();
        let message = "It's me, Marlene, do you miss me?!";
        let hash = hash_message(message.as_bytes());
        let mut signature = wallet.sign_hash(hash).unwrap().to_string();
        // Manipulate the signature, replacing the last character with a '0'
        signature.pop();
        signature.push('0');
        let signature = format!("0x{}", signature);
        let result = recover_eth_address(message, &EthSignature::new(&signature).unwrap());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid recovery ID");
    }

    #[test]
    fn test_recover_eth_address_with_wrong_message() {
        let (wallet, address) = create_wallet();
        let message = "Message 1";
        let wrong_message = "Message 2";
        let hash = hash_message(message.as_bytes());
        let signature = wallet.sign_hash(hash).unwrap().to_string();
        let signature = format!("0x{}", signature);
        let recovered_address =
            recover_eth_address(wrong_message, &EthSignature::new(&signature).unwrap()).unwrap();
        assert_ne!(address, recovered_address);
    }
}

#[cfg(test)]
mod convert_to_eip55 {
    use crate::eth::convert_to_eip55;

    #[test]
    fn test_convert_to_eip55() {
        let valid_address = "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359";
        let valid_address_eip55 = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
        let result = convert_to_eip55(valid_address);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_address_eip55);
    }

    #[test]
    fn test_convert_to_eip55_already_valid() {
        let valid_address_eip55 = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
        let result = convert_to_eip55(valid_address_eip55);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_address_eip55);
    }
}
