use crate::{siwe_message::SiweMessage, siwe_settings::SiweSettings, SETTINGS, SIWE_MESSAGES};
use siwe::{Message, VerificationOpts};
use time::OffsetDateTime;

/// Time to live for SIWE messages in nanoseconds.
/// Equivalent to 5 minutes.
const SIWE_MESSAGE_TTL: u64 = 5 * 60 * 1_000_000_000;

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
pub async fn login(signature: String, address: String) -> Result<String, String> {
    prune_expired_messages();

    let settings = get_siwe_settings()?;
    let signature_bytes = decode_signature(&signature)?;
    let message = get_siwe_message(&address)?;

    verify_message(&message, &signature_bytes, &settings).await?;

    Ok(address)
}

/// Removes SIWE messages that have exceeded their time to live.
pub fn prune_expired_messages() {
    let current_time = ic_cdk::api::time();
    let cutoff_time = current_time - SIWE_MESSAGE_TTL;

    SIWE_MESSAGES.with_borrow_mut(|map| {
        map.retain(|_, message| message.issued_at >= cutoff_time);
    });
}

/// Retrieves the SIWE settings. Returns an error if settings are not initialized.
fn get_siwe_settings() -> Result<SiweSettings, String> {
    SETTINGS
        .get()
        .cloned()
        .ok_or_else(|| String::from("Settings have not been initialized"))
}

/// Decodes the signature string. Skips the "0x" prefix.
fn decode_signature(signature: &str) -> Result<[u8; 65], String> {
    // Skip "0x" prefix
    let bytes = hex::decode(&signature[2..])
        .map_err(|_| String::from("Failed to decode signature due to invalid format"))?;

    let mut signature_bytes = [0u8; 65];
    signature_bytes.clone_from_slice(&bytes);
    Ok(signature_bytes)
}

/// Fetches the SIWE message associated with the provided address.
fn get_siwe_message(address: &str) -> Result<SiweMessage, String> {
    SIWE_MESSAGES
        .with(|map| {
            let map_borrowed = map.borrow();
            map_borrowed.get(address.as_bytes()).cloned()
        })
        .ok_or_else(|| String::from("Message not found for the given address"))
}

/// Verifies the SIWE message using the given signature and settings.
async fn verify_message(
    siwe_message: &SiweMessage,
    signature: &[u8; 65],
    settings: &SiweSettings,
) -> Result<(), String> {
    let message: Message = siwe_message
        .to_erc_4361()
        .parse()
        .map_err(|_| String::from("Failed to parse the message"))?;

    let timestamp = Some(
        OffsetDateTime::from_unix_timestamp_nanos(siwe_message.issued_at as i128)
            .map_err(|_| String::from("Invalid timestamp in the message"))?,
    );

    let verification_opts = VerificationOpts {
        domain: Some(
            settings
                .domain
                .clone()
                .parse()
                .map_err(|_| String::from("Failed to parse the domain from settings"))?,
        ),
        nonce: Some(message.nonce.clone()),
        timestamp,
        ..Default::default()
    };

    message
        .verify(signature, &verification_opts)
        .await
        .map_err(|e| format!("Verification error: {}", e))
}
