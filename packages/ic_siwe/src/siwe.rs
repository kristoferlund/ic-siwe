use crate::settings::Settings;
use crate::{rand::generate_nonce, time::get_current_time};
use crate::{with_settings, SIWE_MESSAGES};

use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Represents a SIWE (Sign-In With Ethereum) message.
///
/// This struct contains all the fields required for a SIWE message as per the EIP-4361 specification.
/// It includes the Ethereum address, domain, statement, and various timestamps.
#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct SiweMessage {
    pub scheme: String,
    pub domain: String,
    pub address: String,
    pub statement: String,
    pub uri: String,
    pub version: u8,
    pub chain_id: u32,
    pub nonce: String,
    pub issued_at: u64,
    pub expiration_time: u64,
}

impl fmt::Display for SiweMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{}", json)
    }
}

impl SiweMessage {
    /// Checks if the SIWE message is currently valid based on its issue and expiration times.
    ///
    /// # Returns
    ///
    /// `true` if the message is currently within its valid time period, `false` otherwise.
    pub fn is_expired(&self) -> bool {
        let current_time = get_current_time();
        self.issued_at < current_time || current_time > self.expiration_time
    }
}

/// Converts the SIWE message to the ERC-4361 string format.
///
/// # Returns
///
/// A string representation of the SIWE message in the ERC-4361 format.
impl From<SiweMessage> for String {
    fn from(val: SiweMessage) -> Self {
        let issued_at_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(val.issued_at as i128).unwrap();
        let issued_at_iso_8601 = issued_at_datetime.format(&Rfc3339).unwrap();

        let expiration_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(val.expiration_time as i128).unwrap();
        let expiration_iso_8601 = expiration_datetime.format(&Rfc3339).unwrap();

        format!(
            "{domain} wants you to sign in with your Ethereum account:\n\
                {address}\n\n\
                {statement}\n\n\
                URI: {uri}\n\
                Version: {version}\n\
                Chain ID: {chain_id}\n\
                Nonce: {nonce}\n\
                Issued At: {issued_at_iso_8601}\n\
                Expiration Time: {expiration_iso_8601}",
            domain = val.domain,
            address = val.address,
            statement = val.statement,
            uri = val.uri,
            version = val.version,
            chain_id = val.chain_id,
            nonce = val.nonce,
        )
    }
}

/// Create SIWE message for the given address.
pub(crate) fn create_siwe_message(address: &str) -> Result<SiweMessage, String> {
    let nonce = generate_nonce()?;

    let message = with_settings!(|settings: &Settings| {
        SiweMessage {
            scheme: settings.scheme.clone(),
            domain: settings.domain.clone(),
            address: address.to_string(),
            statement: settings.statement.clone(),
            uri: settings.uri.clone(),
            version: 1,
            chain_id: settings.chain_id,
            nonce: hex::encode(nonce),
            issued_at: get_current_time(),
            expiration_time: get_current_time().saturating_add(settings.sign_in_expires_in),
        }
    });
    Ok(message)
}

/// Removes SIWE messages that have exceeded their time to live.
pub(crate) fn prune_expired_siwe_messages() {
    let current_time = get_current_time();

    SIWE_MESSAGES.with_borrow_mut(|siwe_message| {
        siwe_message.retain(|_, message| message.expiration_time > current_time);
    });
}

/// Adds a SIWE message to state.
pub(crate) fn add_siwe_message(message: SiweMessage, address_bytes: Vec<u8>) {
    SIWE_MESSAGES.with_borrow_mut(|siwe_message| {
        siwe_message.insert(address_bytes, message);
    });
}

/// Fetches the SIWE message associated with the provided address.
pub(crate) fn get_siwe_message(address_bytes: &Vec<u8>) -> Result<SiweMessage, String> {
    SIWE_MESSAGES.with_borrow(|siwe_message| {
        siwe_message
            .get(address_bytes)
            .cloned()
            .ok_or_else(|| String::from("Message not found for the given address"))
    })
}

/// Removes the SIWE message associated with the provided address.
pub(crate) fn remove_siwe_message(address_bytes: &Vec<u8>) {
    SIWE_MESSAGES.with_borrow_mut(|siwe_message| {
        siwe_message.remove(address_bytes);
    });
}
