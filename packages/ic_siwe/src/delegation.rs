use std::collections::HashMap;

use super::hash::{self, Value};
use crate::{settings::Settings, signature_map::SignatureMap, with_settings};

use ic_certified_map::{Hash, HashTree};
use serde_bytes::ByteBuf;

use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

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

/// The seed is what uniquely identifies the delegation. It is derived from the salt,
/// the Ethereum address and the SIWE message URI.
///
/// # Parameters
///
/// * `address`: The Ethereum address as a string slice.
///
/// # Returns
///
/// A hash value representing the unique seed.
pub fn generate_seed(address: &str) -> Hash {
    with_settings!(|settings: &Settings| {
        let mut seed: Vec<u8> = vec![];

        let salt = settings.salt.as_bytes();
        seed.push(salt.len() as u8);
        seed.extend_from_slice(salt);

        let address = address.as_bytes();
        seed.push(address.len() as u8);
        seed.extend(address);

        let uri = settings.uri.as_bytes();
        seed.push(uri.len() as u8);
        seed.extend(uri);

        hash::hash_bytes(seed)
    })
}

/// Creates a delegation with the provided session key and expiration. The delegation also contains
/// the list of canisters for which the identity delegation is allowed.
///
/// # Parameters
///
/// * `session_key`: A key that uniquely identifies the session.
/// * `expiration`: The expiration time of the delegation in nanoseconds since the UNIX epoch.
pub fn create_delegation(session_key: ByteBuf, expiration: u64) -> Delegation {
    with_settings!(|settings: &Settings| {
        Delegation {
            pubkey: session_key.clone(),
            expiration,
            targets: settings.targets.clone(),
        }
    })
}

/// Constructs a hash tree that acts as a proof that there is a entry (seed_hash/delegation_hash) in
/// the signature map.
///
/// # Parameters
///
/// * `signature_map`: The map of signatures.
/// * `seed`: The unique seed that identifies the delegation.
/// * `delegation_hash`: The hash of the delegation.
pub fn witness(
    signature_map: &SignatureMap,
    seed: Hash,
    delegation_hash: Hash,
) -> Result<HashTree, String> {
    let witness = signature_map
        .witness(hash::hash_bytes(seed), delegation_hash)
        .expect("Signature not found.");

    let witness_hash = witness.reconstruct();
    let root_hash = signature_map.root_hash();
    if witness_hash != root_hash {
        return Err(format!(
            "Internal error: signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
            hex::encode(witness_hash),
            hex::encode(root_hash)
        ));
    }

    Ok(witness)
}

/// Creates a certified signature using a certificate and a state hash tree.
///
/// # Parameters
///
/// * `certificate`: A vector of bytes representing the certificate.
/// * `tree`: The `HashTree` used for certification.
///
/// # Returns
///
/// A `Result` containing a vector of bytes of the certified signature, or an error string.
pub fn create_certified_signature(certificate: Vec<u8>, tree: HashTree) -> Result<Vec<u8>, String> {
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

/// Creates a DER-encoded public key for the user canister using the given seed. This public key will be
/// used to create a self-authenticating principal for the user.
///
/// # Parameters
///
/// * `seed`: A vector of bytes representing the seed.
///
/// # Returns
///
/// A vector of bytes representing the DER-encoded public key.
pub(crate) fn create_user_canister_pubkey(seed: Vec<u8>) -> Vec<u8> {
    let my_canister_id: Vec<u8> = ic_cdk::api::id().as_ref().to_vec();

    let mut bitstring: Vec<u8> = vec![];
    bitstring.push(my_canister_id.len() as u8);
    bitstring.extend(my_canister_id);
    bitstring.extend(seed);

    let mut der: Vec<u8> = vec![];
    // sequence of length 17 + the bit string length
    der.push(0x30);
    der.push(17 + bitstring.len() as u8);
    der.extend(vec![
        // sequence of length 12 for the OID
        0x30, 0x0C, // OID 1.3.6.1.4.1.56387.1.2
        0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xB8, 0x43, 0x01, 0x02,
    ]);
    // BIT string of given length
    der.push(0x03);
    der.push(1 + bitstring.len() as u8);
    der.push(0x00);
    der.extend(bitstring);
    der
}

/// Serializes the given data into CBOR format.
///
/// # Parameters
///
/// * `data`: A reference to the data to be serialized.
///
/// # Returns
///
/// A `Result` containing the CBOR serialized data as a vector of bytes, or an error string.
fn cbor_serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, String> {
    let mut cbor_serializer = serde_cbor::ser::Serializer::new(Vec::new());
    cbor_serializer.self_describe().map_err(|e| e.to_string())?;
    data.serialize(&mut cbor_serializer)
        .map_err(|e| e.to_string())?;

    Ok(cbor_serializer.into_inner())
}
