use crate::{
    types::{settings::get_settings, siwe_message::SiweMessage},
    SESSION_MESSAGES, SIGN_IN_MESSAGES,
};
use candid::Principal;
use siwe::{Message, VerificationOpts};
use time::OffsetDateTime;

/// Attempts to log in using the provided signature and address.
///
/// # Parameters
///
/// - `signature`: The user's signature.
/// - `address`: The address associated with the user.
///
/// # Returns
///
/// - `Ok`: If the login process was successful.
/// - `Err`: Descriptive error message if any step fails.
pub async fn login(
    signature: String,
    address: String,
    principal: Principal,
) -> Result<String, String> {
    prune_expired_messages();

    let signature_bytes = decode_signature(&signature)?;
    let message = get_siwe_message(&address)?;

    verify_message(&message, &signature_bytes).await?;

    SESSION_MESSAGES.with_borrow_mut(|map| {
        map.insert(principal.as_slice().into(), message.clone());
    });

    Ok(address)
}

/// Removes SIWE messages that have exceeded their time to live.
pub fn prune_expired_messages() {
    let current_time = ic_cdk::api::time();

    let sign_in_expires_in = get_settings()
        .map(|settings| settings.sign_in_expires_in)
        .unwrap_or(0);

    let cutoff_time = current_time - sign_in_expires_in;

    SIGN_IN_MESSAGES.with_borrow_mut(|map| {
        map.retain(|_, message| message.issued_at >= cutoff_time);
    });
}

/// Decodes the signature string. Skips the "0x" prefix.
fn decode_signature(signature: &str) -> Result<[u8; 65], String> {
    // Skip "0x" prefix and ensure correct length
    if signature.len() != 2 + 65 * 2 {
        return Err(String::from("Invalid signature length"));
    }

    hex::decode(&signature[2..])
        .map_err(|_| String::from("Failed to decode signature due to invalid format"))
        .and_then(|bytes| {
            let mut signature_bytes = [0u8; 65];
            // Ensure we have exactly 65 bytes
            if bytes.len() == signature_bytes.len() {
                signature_bytes.copy_from_slice(&bytes);
                Ok(signature_bytes)
            } else {
                Err(String::from("Invalid signature length"))
            }
        })
}

/// Fetches the SIWE message associated with the provided address.
fn get_siwe_message(address: &str) -> Result<SiweMessage, String> {
    SIGN_IN_MESSAGES
        .with_borrow(|map| map.get(address.as_bytes()).cloned())
        .ok_or_else(|| String::from("Message not found for the given address"))
}

/// Verifies the SIWE message using the given signature and settings.
async fn verify_message(siwe_message: &SiweMessage, signature: &[u8; 65]) -> Result<(), String> {
    let message: Message = siwe_message
        .to_erc_4361()
        .parse()
        .map_err(|_| "Failed to parse the SIWE message into ERC-4361 format".to_string())?;

    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(siwe_message.issued_at as i128)
        .map_err(|_| "Invalid timestamp in the SIWE message".to_string())?;

    let settings = get_settings()?;

    let verification_opts = VerificationOpts {
        domain: Some(
            settings
                .domain
                .parse()
                .map_err(|_| "Failed to parse the domain from settings".to_string())?,
        ),
        nonce: Some(message.nonce.clone()), // If nonce is not used elsewhere, no need to clone
        timestamp: Some(timestamp),
        ..Default::default() // Ensure this is the intended behavior
    };

    message
        .verify(signature, &verification_opts)
        .await
        .map_err(|e| format!("SIWE message verification error: {}", e))
}
