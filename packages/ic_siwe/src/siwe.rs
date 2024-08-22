use crate::eth::EthAddress;
use crate::settings::Settings;
use crate::time::get_current_time;
use crate::{hash, with_settings};
use candid::{CandidType, Deserialize};
use ic_certified_map::Hash;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug)]
pub enum SiweMessageError {
    MessageNotFound,
}

impl fmt::Display for SiweMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SiweMessageError::MessageNotFound => write!(f, "Message not found"),
        }
    }
}

impl From<SiweMessageError> for String {
    fn from(error: SiweMessageError) -> Self {
        error.to_string()
    }
}

/// Represents a SIWE (Sign-In With Ethereum) message.
///
/// This struct and its implementation methods support all required fields in the [ERC-4361](https://eips.ethereum.org/EIPS/eip-4361)
/// specification.
///
/// # Examples
///
/// The following is an example of a SIWE message formatted according to the [ERC-4361](https://eips.ethereum.org/EIPS/eip-4361) specification:
///
/// ```text
/// 127.0.0.1 wants you to sign in with your Ethereum account:
/// 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
///
/// Login to the app
///
/// URI: http://127.0.0.1:5173
/// Version: 1
/// Chain ID: 10
/// Nonce: ee1ee5ead5b55fe8c8e9
/// Issued At: 2021-05-06T19:17:10Z
/// Expiration Time: 2021-05-06T19:17:13Z
/// ```
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

impl SiweMessage {
    /// Constructs a new `SiweMessage` for a given Ethereum address using the settings defined in the
    /// global [`Settings`] struct.
    ///
    /// # Arguments
    ///
    /// * `address`: The Ethereum address of the user.
    /// * `nonce`: The nonce generated during the [`crate::login::prepare_login`] call.
    pub fn new(address: &EthAddress, nonce: &str) -> SiweMessage {
        let current_time = get_current_time();
        with_settings!(|settings: &Settings| {
            SiweMessage {
                scheme: settings.scheme.clone(),
                domain: settings.domain.clone(),
                address: address.as_str().to_string(),
                statement: settings.statement.clone(),
                uri: settings.uri.clone(),
                version: 1,
                chain_id: settings.chain_id,
                nonce: nonce.to_string(),
                issued_at: get_current_time(),
                expiration_time: current_time.saturating_add(settings.sign_in_expires_in),
            }
        })
    }

    /// Checks if the SIWE message is currently valid.
    ///
    /// # Returns
    ///
    /// `true` if the message is within its valid time period, `false` otherwise.
    pub fn is_expired(&self) -> bool {
        let current_time = get_current_time();
        self.issued_at < current_time || current_time > self.expiration_time
    }
}

impl fmt::Display for SiweMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{}", json)
    }
}

impl From<SiweMessage> for String {
    /// Converts the SIWE message to the [ERC-4361](https://eips.ethereum.org/EIPS/eip-4361) string format.
    ///
    /// # Returns
    ///
    /// A string representation of the SIWE message in the ERC-4361 format.
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

/// The SiweMessageMap map key is the hash of the caller address and the message nonce.
/// This ensures every call to `siwe_prepare_login` leads to one new copy of the SIWE message being stored.
pub fn siwe_message_map_hash(address: &EthAddress, nonce: &str) -> Hash {
    let mut bytes: Vec<u8> = vec![];

    let address_bytes = address.as_bytes();
    bytes.push(address_bytes.len() as u8);
    bytes.extend(address_bytes);

    let nonce_bytes = nonce.as_bytes();
    bytes.push(nonce_bytes.len() as u8);
    bytes.extend(nonce_bytes);

    hash::hash_bytes(bytes)
}

/// The SiweMessageMap is a map of SIWE messages keyed by the Ethereum address of the user. SIWE messages
/// are stored in the map during the course of the login process and are removed once the login process
/// is complete. The map is also pruned periodically to remove expired SIWE messages.
pub struct SiweMessageMap {
    map: HashMap<[u8; 32], SiweMessage>,
}

impl SiweMessageMap {
    pub fn new() -> SiweMessageMap {
        SiweMessageMap {
            map: HashMap::new(),
        }
    }

    /// Removes SIWE messages that have exceeded their time to live.
    pub fn prune_expired(&mut self) {
        let current_time = get_current_time();
        self.map
            .retain(|_, message| message.expiration_time > current_time);
    }

    /// Adds a SIWE message to the map.
    pub fn insert(&mut self, message: SiweMessage, address: &EthAddress, nonce: &str) {
        let hash = siwe_message_map_hash(address, nonce);
        self.map.insert(hash, message);
    }

    /// Returns a cloned SIWE message associated with the provided address or an error if the message
    /// does not exist.
    pub fn get(&self, address: &EthAddress, nonce: &str) -> Result<SiweMessage, SiweMessageError> {
        let hash = siwe_message_map_hash(address, nonce);
        self.map
            .get(&hash)
            .cloned()
            .ok_or(SiweMessageError::MessageNotFound)
    }

    /// Removes the SIWE message associated with the provided address.
    pub fn remove(&mut self, address: &EthAddress, nonce: &str) {
        let hash = siwe_message_map_hash(address, nonce);
        self.map.remove(&hash);
    }
}

impl Default for SiweMessageMap {
    fn default() -> Self {
        Self::new()
    }
}
