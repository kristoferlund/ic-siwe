/// Converts an Ed25519 public key into DER (Distinguished Encoding Rules) format.
/// This is used for encoding the key in a standardized format.
/// The function prepends a fixed DER header to the raw public key.
///
/// # Arguments
/// * `key` - A vector containing the raw public key bytes.
///
/// # Returns
/// A `Vec<u8>` containing the DER-encoded public key.
pub(crate) fn ed25519_public_key_to_der(mut key: Vec<u8>) -> Vec<u8> {
    // DER header for Ed25519 public key
    let mut encoded: Vec<u8> = vec![
        0x30, 0x2A, // Sequence of 42 bytes
        0x30, 0x05, // Sequence of 5 bytes
        0x06, 0x03, // OID of length 3 bytes
        0x2B, 0x65, 0x70, // OID 1.3.101.112
        0x03, 0x21, // Bit string of 33 bytes
        0x00, // No padding
    ];
    // Append the raw public key to the DER header
    encoded.append(&mut key);
    encoded
}

/// Extracts a raw Ed25519 public key from its DER-encoded format.
/// This function is used to retrieve the raw public key bytes from a DER-encoded key.
///
/// # Arguments
/// * `key_der` - A vector containing the DER-encoded public key.
///
/// # Returns
/// A `Vec<u8>` containing the raw public key bytes.
///
/// # Panics
/// Panics if `key_der` is not longer than 12 bytes, indicating an invalid or corrupt DER format.
pub(crate) fn _ed25519_public_key_from_der(mut key_der: Vec<u8>) -> Vec<u8> {
    // Ensure the DER-encoded key is of sufficient length
    assert!(key_der.len() > 12);
    // Remove the DER header to extract the raw public key
    key_der.drain(0..12);
    key_der
}
