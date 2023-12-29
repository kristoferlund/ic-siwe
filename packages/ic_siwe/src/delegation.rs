use std::collections::HashMap;

use super::hash::{self, Value};
use crate::{
    settings::get_settings, signature_map::SignatureMap, time::get_current_time, AssetHashes, STATE,
};
use ic_cdk::{
    api::{data_certificate, set_certified_data},
    trap,
};
use ic_certified_map::{fork_hash, labeled_hash, AsHashTree, Hash, HashTree};
use serde_bytes::ByteBuf;

pub const LABEL_ASSETS: &[u8] = b"http_assets";
pub const LABEL_SIG: &[u8] = b"sig";

const DELEGATION_SIGNATURE_EXPIRES_AT: u64 = 60 * 1_000_000_000; // 1 minute

use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignedDelegationCandidType {
    pub delegation: DelegationCandidType,
    pub signature: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct DelegationCandidType {
    pub pubkey: ByteBuf,
    pub expiration: u64,
    pub targets: Option<Vec<Principal>>,
}

#[derive(Serialize)]
struct CertificateSignature<'a> {
    certificate: ByteBuf,
    tree: HashTree<'a>,
}

pub(crate) fn prepare_delegation(
    address: &str,
    session_key: ByteBuf,
    expiration: u64,
) -> Result<ByteBuf, String> {
    let seed = calculate_seed(address);

    STATE.with(|state| {
        let mut signature_map = state.sigs.borrow_mut();

        prune_expired_signatures(&state.asset_hashes.borrow(), &mut signature_map);
        add_signature(&mut signature_map, session_key, seed, expiration);
        update_root_hash(&state.asset_hashes.borrow(), &signature_map);

        Ok(ByteBuf::from(der_encode_canister_sig_key(seed.to_vec())))
    })
}

pub(crate) fn calculate_seed(address: &str) -> Hash {
    let settings = get_settings().unwrap();

    let mut blob: Vec<u8> = vec![];

    let salt = settings.salt.as_bytes();
    blob.push(salt.len() as u8);
    blob.extend_from_slice(salt);

    let address = address.as_bytes();
    blob.push(address.len() as u8);
    blob.extend(address);

    let uri = settings.uri.as_bytes();
    blob.push(uri.len() as u8);
    blob.extend(uri);

    hash::hash_bytes(blob)
}

pub(crate) fn prune_expired_signatures(
    asset_hashes: &AssetHashes,
    signature_map: &mut SignatureMap,
) {
    const MAX_SIGS_TO_PRUNE: usize = 10;
    let num_pruned = signature_map.prune_expired(get_current_time(), MAX_SIGS_TO_PRUNE);

    if num_pruned > 0 {
        update_root_hash(asset_hashes, signature_map);
    }
}

pub(crate) fn add_signature(
    signature_map: &mut SignatureMap,
    session_key: ByteBuf,
    seed: Hash,
    expiration: u64,
) {
    let delegation_hash = delegation_hash(&DelegationCandidType {
        pubkey: session_key,
        expiration,
        targets: None,
    });

    let signature_expires_at = get_current_time().saturating_add(DELEGATION_SIGNATURE_EXPIRES_AT);

    signature_map.put(
        hash::hash_bytes(seed),
        delegation_hash,
        signature_expires_at,
    );
}

pub(crate) fn delegation_hash(delegation: &DelegationCandidType) -> Hash {
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

pub(crate) fn update_root_hash(asset_hashes: &AssetHashes, signature_map: &SignatureMap) {
    let prefixed_root_hash = fork_hash(
        &labeled_hash(LABEL_ASSETS, &asset_hashes.root_hash()),
        &labeled_hash(LABEL_SIG, &signature_map.root_hash()),
    );
    set_certified_data(&prefixed_root_hash[..]);
}

pub(crate) fn der_encode_canister_sig_key(seed: Vec<u8>) -> Vec<u8> {
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

fn handle_witness<'a>(
    signature_map: &'a SignatureMap,
    seed: Hash,
    delegation_hash: Hash,
    asset_hashes: &'a AssetHashes,
) -> HashTree<'a> {
    let witness = signature_map
        .witness(hash::hash_bytes(seed), delegation_hash)
        .unwrap_or_else(|| trap("Signature not found."));

    let witness_hash = witness.reconstruct();
    let root_hash = signature_map.root_hash();
    if witness_hash != root_hash {
        trap(&format!(
            "Internal error: signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
            hex::encode(witness_hash),
            hex::encode(root_hash)
        ));
    }

    ic_certified_map::fork(
        HashTree::Pruned(ic_certified_map::labeled_hash(
            LABEL_ASSETS,
            &asset_hashes.root_hash(),
        )),
        ic_certified_map::labeled(LABEL_SIG, witness),
    )
}

/// Creates a certified signature.
pub fn create_certified_signature(certificate: Vec<u8>, tree: HashTree) -> Result<Vec<u8>, String> {
    let certificate_signature = CertificateSignature {
        certificate: ByteBuf::from(certificate),
        tree,
    };

    cbor_serialize(&certificate_signature)
}

/// Serializes the given data using CBOR.
pub fn cbor_serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, String> {
    let mut cbor_serializer = serde_cbor::ser::Serializer::new(Vec::new());
    cbor_serializer.self_describe().map_err(|e| e.to_string())?;
    data.serialize(&mut cbor_serializer)
        .map_err(|e| e.to_string())?;

    Ok(cbor_serializer.into_inner())
}

pub fn get_signature(
    asset_hashes: &AssetHashes,
    signature_map: &SignatureMap,
    session_key: ByteBuf,
    seed: Hash,
    expiration: u64,
) -> Result<Vec<u8>, String> {
    let certificate =
        data_certificate().ok_or("get_signature must be called using a QUERY call")?;

    let delegation_hash = delegation_hash(&DelegationCandidType {
        pubkey: session_key.clone(),
        expiration,
        targets: None,
    });

    let tree = handle_witness(signature_map, seed, delegation_hash, asset_hashes);

    create_certified_signature(certificate, tree)
}
