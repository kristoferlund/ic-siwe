use libsecp256k1::{recover, Message, PublicKey, RecoveryId, Signature};
use sha3::{Digest, Keccak256};

/// Recovers an Ethereum address from a given message and signature.
///
/// # Arguments
///
/// * `message` - A string slice representing the message.
/// * `signature` - A string slice representing the hex-encoded signature.
///
/// # Returns
///
/// A `Result` which is `Ok` with the recovered address as a `String` if successful, or an `Err` with a `String` error message.
///
/// # Examples
///
/// ```
/// let address = recover_address("Hello, world!", "0x...").unwrap();
/// println!("Recovered address: {}", address);
/// ```
pub(crate) fn recover_address(message: &str, signature: &str) -> Result<String, String> {
    let signature_bytes = decode_signature(signature)?;
    let (recovery_id, signature) = parse_signature(signature_bytes)?;

    let message_hash = eip191_hash(message)?;
    let message = Message::parse(&message_hash);

    let public_key = recover_public_key(&message, &signature, &recovery_id)?;
    let recovered_address = derive_address_from_public_key(&public_key)?;

    Ok(recovered_address)
}

/// Decodes a hex-encoded signature string.
///
/// # Arguments
///
/// * `signature` - A mutable string slice of the hex-encoded signature.
///
/// # Returns
///
/// A `Result` containing either a `Vec<u8>` of the decoded signature or a `String` error message.
pub(crate) fn decode_signature(mut signature: &str) -> Result<Vec<u8>, String> {
    signature = signature.strip_prefix("0x").unwrap_or(signature);
    if signature.len() != 65 * 2 {
        return Err(String::from("Invalid signature length"));
    }

    hex::decode(signature)
        .map_err(|_| String::from("Failed to decode signature due to invalid format"))
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|_| String::from("Invalid signature length"))
        })
}

/// Parses a signature byte array and extracts the recovery ID and signature.
///
/// # Arguments
///
/// * `signature` - A `Vec<u8>` representing the signature bytes.
///
/// # Returns
///
/// A `Result` containing either a tuple of `(RecoveryId, Signature)` or a `String` error message.
pub(crate) fn parse_signature(signature: Vec<u8>) -> Result<(RecoveryId, Signature), String> {
    let mut signature = signature;
    let recovery_byte = signature
        .pop()
        .ok_or_else(|| "No recovery byte in signature".to_string())?;
    let recovery_id =
        RecoveryId::parse_rpc(recovery_byte).map_err(|_| "Invalid recovery byte".to_string())?;

    let signature_bytes: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid signature length".to_string())?;

    let signature = Signature::parse_standard(&signature_bytes)
        .map_err(|_| "Failed to parse signature".to_string())?;

    Ok((recovery_id, signature))
}

/// Hashes a message using the EIP-191 standard.
///
/// # Arguments
///
/// * `message` - A string slice representing the message to hash.
///
/// # Returns
///
/// A `Result` containing either a `[u8; 32]` array representing the hashed message or a `String` error message.
pub(crate) fn eip191_hash(message: &str) -> Result<[u8; 32], String> {
    Ok(Keccak256::default()
        .chain_update(eip191_bytes(message)?)
        .finalize()
        .into())
}

/// Formats a message according to the EIP-191 standard.
///
/// # Arguments
///
/// * `message` - A string slice of the message to format.
///
/// # Returns
///
/// A `Result` containing either a `Vec<u8>` of the formatted message or a `String` error message.
pub(crate) fn eip191_bytes(message: &str) -> Result<Vec<u8>, String> {
    let s = message.to_string();
    Ok(format!("\x19Ethereum Signed Message:\n{}{}", s.as_bytes().len(), s).into())
}

/// Recovers the public key from a given message, signature, and recovery ID.
///
/// # Arguments
///
/// * `message` - A reference to a `Message`.
/// * `signature` - A reference to a `Signature`.
/// * `recovery_id` - A reference to a `RecoveryId`.
///
/// # Returns
///
/// A `Result` containing either a `PublicKey` or a `String` error message.
pub(crate) fn recover_public_key(
    message: &Message,
    signature: &Signature,
    recovery_id: &RecoveryId,
) -> Result<PublicKey, String> {
    recover(message, signature, recovery_id).map_err(|_| "Failed to recover public key".to_string())
}

/// Derives the Ethereum address from a public key.
///
/// # Arguments
///
/// * `key` - A reference to a `PublicKey`.
///
/// # Returns
///
/// A `Result` containing either a `String` of the Ethereum address or a `String` error message.
pub(crate) fn derive_address_from_public_key(key: &PublicKey) -> Result<String, String> {
    let key_bytes = key.serialize();
    let keccak256: [u8; 32] = Keccak256::new()
        .chain_update(&key_bytes[1..]) // Skip the first byte
        .finalize()
        .into();

    let keccak256_hex = hex::encode(keccak256);
    Ok(convert_to_eip55(&keccak256_hex[24..])) // Get last 20 bytes as address
}

/// Converts an Ethereum address into EIP-55 format.
///
/// # Arguments
///
/// * `addr` - A string slice representing the Ethereum address.
///
/// # Returns
///
/// A `String` containing the Ethereum address in EIP-55 format.
pub(crate) fn convert_to_eip55(addr: &str) -> String {
    let hash = Keccak256::digest(addr.as_bytes());
    "0x".chars()
        .chain(addr.chars().enumerate().map(|(i, c)| {
            match (c, hash[i >> 1] & if i % 2 == 0 { 128 } else { 8 } != 0) {
                ('a'..='f' | 'A'..='F', true) => c.to_ascii_uppercase(),
                _ => c.to_ascii_lowercase(),
            }
        }))
        .collect()
}
