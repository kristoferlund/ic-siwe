use crate::{eth::EthAddress, hash, settings::Settings, time::get_current_time, with_settings};
use candid::{CandidType, Deserialize, Principal};
use ic_certified_map::Hash;
use serde::Serialize;
use std::{collections::HashMap, fmt};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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
    /// * `nonce`: The nonce for the SIWE message (handled internally by the library).
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
        current_time < self.issued_at || current_time > self.expiration_time
    }
}

impl fmt::Display for SiweMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{json}")
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

/// The SiweMessageMap map key is the hash of the Ethereum address and a principal. Since a new
/// principal is generated for each login attempt, the map key is unique for each login attempt.
pub fn siwe_message_map_hash(address: &EthAddress, principal: &Principal) -> Hash {
    let mut bytes: Vec<u8> = vec![];

    let address_bytes = address.as_bytes();
    bytes.extend_from_slice(&(address_bytes.len() as u32).to_le_bytes());
    bytes.extend(address_bytes);

    bytes.extend_from_slice(&(principal.as_slice().len() as u32).to_le_bytes());
    bytes.extend(principal.as_slice());

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
    pub fn insert(&mut self, message: SiweMessage, address: &EthAddress, principal: &Principal) {
        let hash = siwe_message_map_hash(address, principal);
        self.map.insert(hash, message);
    }

    /// Returns a cloned SIWE message associated with the provided address or an error if the message
    /// does not exist.
    pub fn get(
        &self,
        address: &EthAddress,
        principal: &Principal,
    ) -> Result<SiweMessage, SiweMessageError> {
        let hash = siwe_message_map_hash(address, principal);
        self.map
            .get(&hash)
            .cloned()
            .ok_or(SiweMessageError::MessageNotFound)
    }

    /// Removes the SIWE message associated with the provided address.
    pub fn remove(&mut self, address: &EthAddress, principal: &Principal) {
        let hash = siwe_message_map_hash(address, principal);
        self.map.remove(&hash);
    }
}

impl Default for SiweMessageMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::EthAddress;
    use candid::Principal;
    use ethers::{
        core::rand::thread_rng,
        signers::{LocalWallet, Signer},
        utils::to_checksum,
    };

    fn make_message(issued_at: u64, expiration_time: u64) -> SiweMessage {
        SiweMessage {
            scheme: "https".to_string(),
            domain: "example.com".to_string(),
            address: "0x5aAeb6053F3E94C9b9a09f33669435E7Ef1BeAed".to_string(),
            statement: "Test".to_string(),
            uri: "https://example.com".to_string(),
            version: 1,
            chain_id: 1,
            nonce: "abcd".to_string(),
            issued_at,
            expiration_time,
        }
    }

    #[test]
    fn siwe_message_is_expired_logic() {
        let now = get_current_time();
        let msg = make_message(now, now + 1_000_000);
        assert!(!msg.is_expired(), "fresh message should not be expired");

        let past = now.saturating_sub(1_000_000);
        let msg = make_message(past, past + 10);
        // give it time to certainly be past expiration
        assert!(msg.is_expired(), "past-expired message should be expired");

        // message issued in the future should be considered not yet valid (expired=true)
        let future = now.saturating_add(10_000_000);
        let msg = make_message(future, future + 20_000_000);
        assert!(
            msg.is_expired(),
            "future-issued message should be expired/not yet valid"
        );
    }

    #[test]
    fn siwe_message_map_insert_get_remove_and_prune() {
        let addr = {
            let w = LocalWallet::new(&mut thread_rng());
            to_checksum(&w.address(), None)
        };
        let address = EthAddress::new(&addr).unwrap();
        let p1 = Principal::from_slice(&[1; 29]);
        let p2 = Principal::from_slice(&[2; 29]);

        let now = get_current_time();
        let valid = make_message(now, now + 1_000_000_000);
        let expired = make_message(
            now.saturating_sub(2_000_000_000),
            now.saturating_sub(1_000_000_000),
        );

        let mut map = SiweMessageMap::new();
        map.insert(valid.clone(), &address, &p1);
        map.insert(expired, &address, &p2);

        // get works for matching principal/address
        let fetched = map.get(&address, &p1).unwrap();
        assert_eq!(fetched.nonce, valid.nonce);

        // get fails for different principal
        assert!(map.get(&address, &p2).is_ok());
        let p3 = Principal::from_slice(&[3; 29]);
        assert!(matches!(
            map.get(&address, &p3),
            Err(SiweMessageError::MessageNotFound)
        ));

        // prune should remove the expired entry (for p2) but keep the valid one
        map.prune_expired();
        assert!(map.get(&address, &p1).is_ok());
        assert!(matches!(
            map.get(&address, &p2),
            Err(SiweMessageError::MessageNotFound)
        ));

        // remove should delete the remaining entry
        map.remove(&address, &p1);
        assert!(matches!(
            map.get(&address, &p1),
            Err(SiweMessageError::MessageNotFound)
        ));
    }

    #[test]
    fn test_siwe_message_map_hash_no_collision() {
        // Test that the hash function doesn't have collisions for edge case lengths
        let address = EthAddress::new("0x1111111111111111111111111111111111111111").unwrap();

        // Create principals with different lengths (Principal max size is 29 bytes)
        let principal_28 = Principal::from_slice(&[1u8; 28]);
        let principal_29 = Principal::from_slice(&[1u8; 29]);
        let principal_10 = Principal::from_slice(&[1u8; 10]);
        let principal_0 = Principal::from_slice(&[]);

        // Calculate hashes
        let hash_28 = siwe_message_map_hash(&address, &principal_28);
        let hash_29 = siwe_message_map_hash(&address, &principal_29);
        let hash_10 = siwe_message_map_hash(&address, &principal_10);
        let hash_0 = siwe_message_map_hash(&address, &principal_0);

        // Verify all hashes are different
        assert_ne!(hash_28, hash_29, "Hash collision between length 28 and 29");
        assert_ne!(hash_29, hash_10, "Hash collision between length 29 and 10");
        assert_ne!(hash_0, hash_29, "Hash collision between length 0 and 29");
        assert_ne!(hash_28, hash_10, "Hash collision between length 28 and 10");
        assert_ne!(hash_0, hash_28, "Hash collision between length 0 and 28");
        assert_ne!(hash_0, hash_10, "Hash collision between length 0 and 10");

        // Also test with different addresses but same principal
        let address2 = EthAddress::new("0x2222222222222222222222222222222222222222").unwrap();
        let hash_addr2 = siwe_message_map_hash(&address2, &principal_28);
        assert_ne!(
            hash_28, hash_addr2,
            "Hash collision between different addresses"
        );

        // Also test that the old bug would have caused collisions
        // Simulate what would happen with the old u8 casting for length 256
        // (256 as u8 = 0, 257 as u8 = 1, etc)
        let address3 = EthAddress::new("0x3333333333333333333333333333333333333333").unwrap();

        // Create test data to verify the fix prevents collisions that would have occurred
        // with u8 length encoding (this doesn't test actual 256-byte principals since they're invalid)
        let mut test_bytes1 = vec![];
        test_bytes1.extend_from_slice(&(0u32).to_le_bytes()); // What 256 as u8 would give
        test_bytes1.extend(address3.as_bytes());
        test_bytes1.extend_from_slice(&(10u32).to_le_bytes());
        test_bytes1.extend(&vec![1u8; 10]);

        let mut test_bytes2 = vec![];
        test_bytes2.extend_from_slice(&(256u32).to_le_bytes()); // Actual 256
        test_bytes2.extend(address3.as_bytes());
        test_bytes2.extend_from_slice(&(10u32).to_le_bytes());
        test_bytes2.extend(&vec![1u8; 10]);

        // These would have been the same with u8 casting but are different with u32
        assert_ne!(
            hash::hash_bytes(test_bytes1),
            hash::hash_bytes(test_bytes2),
            "Fix prevents collision that would occur with u8 length encoding"
        );
    }
}
