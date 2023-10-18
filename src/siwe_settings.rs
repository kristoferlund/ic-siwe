extern crate serde;
extern crate serde_json;

use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Represents a SIWE (Sign-In With Ethereum) message.
///
/// This struct contains all the fields required for a SIWE message as per the EIP-4361 specification.
#[derive(CandidType, Deserialize, Serialize)]
pub struct SiweMessage {
    pub scheme: String,
    pub domain: String,
    pub address: String,
    pub statement: String,
    pub uri: String,
    pub version: u8,
    pub chain_id: u32,
    pub nonce: [u8; 10],
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
    pub fn to_erc_4361(&self) -> String {
        let issued_at_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(self.issued_at as i128).unwrap();
        let issued_at_iso_8601 = issued_at_datetime.format(&Rfc3339).unwrap();

        let expiration_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(self.expiration_time as i128).unwrap();
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
            domain = self.domain,
            address = self.address,
            statement = self.statement,
            uri = self.uri,
            version = self.version,
            chain_id = self.chain_id,
            nonce = hex::encode(&self.nonce),
        )
    }
}

/// Represents the settings for initializing SIWE.
///
/// This struct is used to pass settings to the `init` function for SIWE configuration.
#[derive(Default)]
pub struct SiweSettings {
    pub domain: String,
    pub scheme: String,
    pub statement: String,
    pub uri: String,
    pub chain_id: u32,
    pub expires_in: u32,
}
pub struct SiweSettingsBuilder {
    settings: SiweSettings,
}

impl SiweSettingsBuilder {
    pub fn new(domain: String, uri: String) -> Self {
        SiweSettingsBuilder {
            settings: SiweSettings {
                domain,
                uri,
                chain_id: 1, // default to Ethereum mainnet
                scheme: String::from("https"),
                statement: String::from("SIWE Fields:"),
                expires_in: 60 * 60 * 24, // 24 hours
            },
        }
    }

    pub fn chain_id(mut self, chain_id: u32) -> Self {
        self.settings.chain_id = chain_id;
        self
    }

    pub fn scheme(mut self, scheme: String) -> Self {
        self.settings.scheme = scheme;
        self
    }

    pub fn statement(mut self, statement: String) -> Self {
        self.settings.statement = statement;
        self
    }

    pub fn expires_in(mut self, expires_in: u32) -> Self {
        self.settings.expires_in = expires_in;
        self
    }

    pub fn build(self) -> SiweSettings {
        self.settings
    }
}
