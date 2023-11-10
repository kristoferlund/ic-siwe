extern crate serde;
extern crate serde_json;

use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::utils::time::get_current_time;

/// Represents a SIWE (Sign-In With Ethereum) message.
///
/// This struct contains all the fields required for a SIWE message as per the EIP-4361 specification.
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
            nonce = self.nonce,
        )
    }

    pub fn is_valid(&self) -> bool {
        let current_time = get_current_time();
        self.issued_at <= current_time && self.expiration_time >= current_time
    }
}
