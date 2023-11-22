use libsecp256k1::{recover, Message, PublicKey, RecoveryId, Signature};
use sha3::{Digest, Keccak256};

pub(crate) fn recover_address(message: &str, signature: &str) -> Result<String, String> {
    let signature_bytes = decode_signature(signature)?;
    let (recovery_id, signature) = parse_signature(signature_bytes)?;

    let message_hash = eip191_hash(message)?;
    let message = Message::parse(&message_hash);

    let public_key = recover_public_key(&message, &signature, &recovery_id)?;
    let recovered_address = derive_address_from_public_key(&public_key)?;

    Ok(recovered_address)
}

/// Decodes the signature string. Skips the "0x" prefix.
pub(crate) fn decode_signature(mut signature: &str) -> Result<Vec<u8>, String> {
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

/// Parses the signature and extracts recovery ID and signature bytes.
pub(crate) fn parse_signature(signature: Vec<u8>) -> Result<(RecoveryId, Signature), String> {
    let mut signature = signature;
    let recovery_byte = signature.pop().ok_or("No recovery byte in signature")?;
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

pub(crate) fn eip191_hash(message: &str) -> Result<[u8; 32], String> {
    Ok(Keccak256::default()
        .chain_update(eip191_bytes(message)?)
        .finalize()
        .into())
}

pub(crate) fn eip191_bytes(message: &str) -> Result<Vec<u8>, String> {
    let s = message.to_string();
    Ok(format!("\x19Ethereum Signed Message:\n{}{}", s.as_bytes().len(), s).into())
}

/// Recovers the public key from the message, signature, and recovery ID.
pub(crate) fn recover_public_key(
    message: &Message,
    signature: &Signature,
    recovery_id: &RecoveryId,
) -> Result<PublicKey, String> {
    recover(message, signature, recovery_id).map_err(|_| "Failed to recover public key".to_string())
}

/// Derives the Ethereum address from the public key.
pub(crate) fn derive_address_from_public_key(key: &PublicKey) -> Result<String, String> {
    let key_bytes = key.serialize();
    let keccak256: [u8; 32] = Keccak256::new()
        .chain_update(&key_bytes[1..]) // Skip the first byte
        .finalize()
        .into();

    let keccak256_hex = hex::encode(keccak256);
    Ok(convert_to_eip55(&keccak256_hex[24..])) // Get last 20 bytes as address
}

/// Takes an eth address and returns it as a checksum formatted string.
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
