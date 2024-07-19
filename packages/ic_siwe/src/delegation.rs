use std::{collections::HashMap, fmt};

use super::hash::{self, Value};
use crate::{
    eth::EthAddress,
    settings::{RuntimeFeature, Settings},
    signature_map::SignatureMap,
    time::get_current_time,
    with_settings,
};

use ic_certified_map::{Hash, HashTree};
use serde_bytes::ByteBuf;

use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use simple_asn1::{from_der, oid, ASN1Block, ASN1EncodeErr};

#[derive(Debug)]
pub enum DelegationError {
    SignatureNotFound,
    WitnessHashMismatch(Hash, Hash),
    SerializationError(String),
    InvalidSessionKey(String),
    InvalidExpiration(String),
    SignatureExpired,
}

impl fmt::Display for DelegationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelegationError::SignatureNotFound => write!(f, "Signature not found"),
            DelegationError::WitnessHashMismatch(witness_hash, root_hash) => write!(
                f,
                "Internal error: signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
                hex::encode(witness_hash),
                hex::encode(root_hash)
            ),
            DelegationError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            DelegationError::InvalidSessionKey(e) => write!(f, "Invalid session key: {}", e),
            DelegationError::InvalidExpiration(e) => write!(f, "Invalid expiration: {}", e),
            DelegationError::SignatureExpired => write!(f, "Signature expired"),
        }
    }
}

impl From<DelegationError> for String {
    fn from(error: DelegationError) -> Self {
        error.to_string()
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Delegation {
    pub pubkey: ByteBuf,
    pub expiration: u64,
    pub targets: Option<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: ByteBuf,
}

#[derive(Serialize)]
struct CertificateSignature<'a> {
    certificate: ByteBuf,
    tree: HashTree<'a>,
}

/// Generates a unique seed for delegation, derived from the salt, Ethereum address, and SIWE message URI.
///
/// # Parameters
/// * `address`: The Ethereum address as a string slice.
///
/// # Returns
/// A `Hash` value representing the unique seed.
pub fn generate_seed(address: &EthAddress) -> Hash {
    with_settings!(|settings: &Settings| {
        let mut seed: Vec<u8> = vec![];

        let salt = settings.salt.as_bytes();
        seed.push(salt.len() as u8);
        seed.extend_from_slice(salt);

        let address_bytes = address.as_str().as_bytes();
        seed.push(address_bytes.len() as u8);
        seed.extend(address_bytes);

        // Only include the URI in the seed if the runtime feature is enabled
        match settings.runtime_features {
            Some(ref features) if features.contains(&RuntimeFeature::IncludeUriInSeed) => {
                let uri = settings.uri.as_bytes();
                seed.push(uri.len() as u8);
                seed.extend_from_slice(uri);
            }
            _ => (),
        }

        hash::hash_bytes(seed)
    })
}

/// Creates a delegation with the provided session key and expiration, including a list of canisters for identity delegation.
///
/// # Parameters
/// * `session_key`: A key uniquely identifying the session.
/// * `expiration`: Expiration time in nanoseconds since the UNIX epoch.
pub fn create_delegation(
    session_key: ByteBuf,
    expiration: u64,
) -> Result<Delegation, DelegationError> {
    // Validate the session key and expiration
    if session_key.is_empty() {
        return Err(DelegationError::InvalidSessionKey(
            "Session key is empty".to_string(),
        ));
    }

    // Validate the session key is DER-encoded
    from_der(&session_key).map_err(|e| {
        DelegationError::InvalidSessionKey(format!("Session key should be DER-encoded: {}", e))
    })?;

    if expiration == 0 {
        return Err(DelegationError::InvalidExpiration(
            "Expiration is 0".to_string(),
        ));
    }
    with_settings!(|settings: &Settings| {
        Ok(Delegation {
            pubkey: session_key.clone(),
            expiration,
            targets: settings.targets.clone(),
        })
    })
}

/// Constructs a hash tree as proof of an entry in the signature map.
///
/// # Parameters
/// * `signature_map`: The map of signatures.
/// * `seed`: The unique seed identifying the delegation.
/// * `delegation_hash`: The hash of the delegation.
pub fn witness(
    signature_map: &SignatureMap,
    seed: Hash,
    delegation_hash: Hash,
) -> Result<HashTree, DelegationError> {
    let seed_hash = hash::hash_bytes(seed);

    if signature_map.is_expired(get_current_time(), seed_hash, delegation_hash) {
        return Err(DelegationError::SignatureExpired);
    }

    let witness = signature_map
        .witness(seed_hash, delegation_hash)
        .ok_or(DelegationError::SignatureNotFound)?;

    let witness_hash = witness.reconstruct();
    let root_hash = signature_map.root_hash();
    if witness_hash != root_hash {
        return Err(DelegationError::WitnessHashMismatch(
            witness_hash,
            root_hash,
        ));
    }

    Ok(witness)
}

/// Creates a certified signature using a certificate and a state hash tree.
///
/// # Parameters
/// * `certificate`: Bytes representing the certificate.
/// * `tree`: The `HashTree` used for certification.
///
/// # Returns
/// A `Result` containing the certified signature or an error.
pub fn create_certified_signature(
    certificate: Vec<u8>,
    tree: HashTree,
) -> Result<Vec<u8>, DelegationError> {
    let certificate_signature = CertificateSignature {
        certificate: ByteBuf::from(certificate),
        tree,
    };

    cbor_serialize(&certificate_signature)
}

pub fn create_delegation_hash(delegation: &Delegation) -> Hash {
    let mut delegation_map = HashMap::new();

    delegation_map.insert("pubkey", Value::Bytes(&delegation.pubkey));
    delegation_map.insert("expiration", Value::U64(delegation.expiration));

    if let Some(targets) = delegation.targets.as_ref() {
        let mut arr = Vec::with_capacity(targets.len());
        for t in targets.iter() {
            arr.push(Value::Bytes(t.as_ref()));
        }
        delegation_map.insert("targets", Value::Array(arr));
    }

    let delegation_map_hash = hash::hash_of_map(delegation_map);

    hash::hash_with_domain(b"ic-request-auth-delegation", &delegation_map_hash)
}

/// Creates a DER-encoded public key for a user canister from a given seed.
///
/// # Parameters
/// * `seed`: Bytes representing the seed.
/// * `canister_id`: The principal of the canister for which the public key is created.
///
/// # Returns
/// Bytes of the DER-encoded public key.
pub(crate) fn create_user_canister_pubkey(
    canister_id: &Principal,
    seed: Vec<u8>,
) -> Result<Vec<u8>, ASN1EncodeErr> {
    let canister_id: Vec<u8> = canister_id.as_slice().to_vec();

    let mut key: Vec<u8> = vec![];
    key.push(canister_id.len() as u8);
    key.extend(canister_id);
    key.extend(seed);

    let algorithm = oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2);
    let algorithm = ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, algorithm)]);
    let subject_public_key = ASN1Block::BitString(0, key.len() * 8, key.to_vec());
    let subject_public_key_info = ASN1Block::Sequence(0, vec![algorithm, subject_public_key]);
    simple_asn1::to_der(&subject_public_key_info)
}

/// Serializes data into CBOR format.
///
/// # Parameters
/// * `data`: The data to serialize.
///
/// # Returns
/// A `Result` containing CBOR serialized data or an error.
fn cbor_serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, DelegationError> {
    let mut cbor_serializer = serde_cbor::ser::Serializer::new(Vec::new());

    cbor_serializer
        .self_describe()
        .map_err(|e| DelegationError::SerializationError(e.to_string()))?;

    data.serialize(&mut cbor_serializer)
        .map_err(|e| DelegationError::SerializationError(e.to_string()))?;

    Ok(cbor_serializer.into_inner())
}

#[cfg(test)]
mod tests {

    use ic_certified_map::labeled_hash;
    use simple_asn1::from_der;

    use crate::{settings::SettingsBuilder, SETTINGS};

    use super::*;

    pub const SESSION_KEY: &[u8] = &[
        48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 220, 227, 2, 129, 72, 36, 43, 220, 96, 102,
        225, 92, 98, 163, 114, 182, 117, 181, 51, 15, 219, 197, 104, 55, 123, 245, 74, 181, 35,
        181, 171, 196,
    ]; // DER encoded session key

    fn init() -> EthAddress {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .targets(vec![Principal::from_text("aaaaa-aa").unwrap()]);
        let settings = builder.build().unwrap();
        SETTINGS.set(Some(settings));
        EthAddress::new("0x1111111111111111111111111111111111111111").unwrap()
    }

    #[test]
    fn test_generate_seed() {
        let address = init();
        let seed = generate_seed(&address);
        assert!(!seed.is_empty(), "Seed should not be empty");
        // Additional assertions can be added here
    }

    #[test]
    fn test_create_delegation() {
        init();
        let session_key = ByteBuf::from(SESSION_KEY);
        let expiration = 123456789;
        let delegation = create_delegation(session_key.clone(), expiration).unwrap();
        assert_eq!(delegation.pubkey, session_key, "Session key should match");
        assert_eq!(delegation.expiration, expiration, "Expiration should match");
        assert_eq!(
            delegation.targets,
            Some(vec![Principal::from_text("aaaaa-aa").unwrap(),]),
            "Targets should match"
        );
    }

    #[test]
    fn test_create_delegation_invalid_session_key() {
        init();
        let session_key = ByteBuf::new(); // Empty session key
        let expiration = 123456789;
        let result = create_delegation(session_key, expiration);
        assert!(result.is_err(), "Result should be an error");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid session key: Session key is empty",
            "Error message should match"
        );
    }

    #[test]
    fn test_create_delegation_invalid_expiration() {
        init();
        let session_key = ByteBuf::from(SESSION_KEY);
        let expiration = 0; // Invalid expiration
        let result = create_delegation(session_key, expiration);
        assert!(result.is_err(), "Result should be an error");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid expiration: Expiration is 0",
            "Error message should match"
        );
    }

    #[test]
    fn test_witness_single_entry() {
        let address = init();
        let seed = generate_seed(&address);
        let session_key = ByteBuf::from(SESSION_KEY);
        let expiration = 123456789;
        let delegation = create_delegation(session_key.clone(), expiration).unwrap();
        let delegation_hash = create_delegation_hash(&delegation);
        let mut signature_map = SignatureMap::default();
        signature_map.put(hash::hash_bytes(seed), delegation_hash);
        let tree = witness(&signature_map, seed, delegation_hash).unwrap();
        let witness_hash = tree.reconstruct();
        let root_hash = signature_map.root_hash();
        assert_eq!(witness_hash, root_hash);
    }

    #[test]
    fn test_witness_multiple_entries() {
        let address = init();
        let seed = generate_seed(&address);
        let session_key = ByteBuf::from(SESSION_KEY);
        let expiration = 123456789;
        let delegation = create_delegation(session_key.clone(), expiration).unwrap();
        let delegation_hash = create_delegation_hash(&delegation);
        let mut signature_map = SignatureMap::default();
        signature_map.put(hash::hash_bytes(seed), delegation_hash);
        let tree = witness(&signature_map, seed, delegation_hash).unwrap();
        let witness_hash = tree.reconstruct();
        let root_hash = signature_map.root_hash();
        assert_eq!(witness_hash, root_hash);

        let session_key = ByteBuf::from([
            48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 228, 25, 195, 240, 251, 10, 105, 44, 189,
            126, 49, 187, 62, 205, 22, 150, 125, 41, 1, 32, 75, 200, 227, 140, 98, 246, 179, 10,
            192, 228, 168, 111,
        ]);
        let delegation = create_delegation(session_key.clone(), expiration).unwrap();
        let delegation_hash = create_delegation_hash(&delegation);
        signature_map.put(hash::hash_bytes(seed), delegation_hash);
        let tree = witness(&signature_map, seed, delegation_hash).unwrap();
        let witness_hash = tree.reconstruct();
        let root_hash = signature_map.root_hash();
        assert_eq!(witness_hash, root_hash);
    }

    #[test]
    fn test_witness_empty_signature_map() {
        let address = init();
        let seed = generate_seed(&address);
        let session_key = ByteBuf::from(SESSION_KEY);
        let expiration = 123456789;
        let delegation = create_delegation(session_key.clone(), expiration).unwrap();
        let delegation_hash = create_delegation_hash(&delegation);
        let signature_map = SignatureMap::default();
        let result = witness(&signature_map, seed, delegation_hash);
        assert!(result.is_err(), "Result should be an error");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Signature not found",
            "Error message should match"
        );
    }

    #[test]
    fn test_witness_hash_not_found() {
        let address = init();
        let seed = generate_seed(&address);
        let session_key = ByteBuf::from(SESSION_KEY);
        let expiration = 123456789;
        let delegation = create_delegation(session_key.clone(), expiration).unwrap();
        let delegation_hash = create_delegation_hash(&delegation);
        let mut signature_map = SignatureMap::default();
        signature_map.put(hash::hash_bytes(vec![1, 2, 3]), delegation_hash);
        let result = witness(&signature_map, seed, delegation_hash);
        assert!(result.is_err(), "Result should be an error");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Signature not found",
            "Error message should match"
        );
    }

    #[test]
    fn test_create_certified_signature() {
        let address = init();
        let seed = generate_seed(&address);
        let session_key = ByteBuf::from(SESSION_KEY);
        let expiration = 123456789;
        let delegation = create_delegation(session_key.clone(), expiration).unwrap();
        let delegation_hash = create_delegation_hash(&delegation);
        let mut signature_map = SignatureMap::default();
        signature_map.put(hash::hash_bytes(seed), delegation_hash);
        let witness = witness(&signature_map, seed, delegation_hash).unwrap();
        let tree = HashTree::Pruned(labeled_hash(b"sig", &witness.reconstruct()));
        let certificate = vec![1, 2, 3];
        let result = create_certified_signature(certificate, tree);
        assert!(result.is_ok(), "Result should be ok");
        let signature = result.unwrap();
        assert!(!signature.is_empty(), "Signature should not be empty");
    }

    #[test]
    fn test_create_user_canister_pubkey() {
        let address = init();
        let seed = generate_seed(&address);
        let result =
            create_user_canister_pubkey(&Principal::from_text("aaaaa-aa").unwrap(), seed.to_vec());
        assert!(result.is_ok());
        let pubkey = result.unwrap();
        let result = from_der(&pubkey);
        assert!(
            result.is_ok(),
            "Result should be a valid DER-encoded public key"
        );
    }

    #[test]
    fn test_cbor_serialize() {
        let cbor = cbor_serialize(&vec![1, 2, 3]).unwrap();
        assert!(!cbor.is_empty(), "CBOR should not be empty");
        let deserialized = serde_cbor::from_slice::<Vec<u8>>(&cbor).unwrap();
        assert_eq!(
            deserialized,
            vec![1, 2, 3],
            "Deserialized CBOR should match"
        );
    }
}
