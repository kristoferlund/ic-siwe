use crate::{
    types::{
        delegation::{Delegation, SignedDelegation},
        signature_map::SignatureMap,
        state::AssetHashes,
    },
    utils::{
        delegation::{calculate_seed, delegation_hash, LABEL_ASSETS, LABEL_SIG},
        eth::validate_eth_address,
        hash,
    },
    STATE,
};
use ic_cdk::{api::data_certificate, trap};
use ic_certified_map::{AsHashTree, Hash, HashTree};
use serde::Serialize;
use serde_bytes::ByteBuf;

#[derive(Serialize)]
struct CertificateSignature<'a> {
    certificate: ByteBuf,
    tree: HashTree<'a>,
}

pub fn get_delegation(
    address: &str,
    session_key: ByteBuf,
    expiration: u64,
) -> Result<SignedDelegation, String> {
    validate_eth_address(address)?;

    let seed = calculate_seed(address);

    STATE.with(|state| {
        get_signature(
            &state.asset_hashes.borrow(),
            &state.sigs.borrow(),
            session_key.clone(),
            seed,
            expiration,
        )
        .map(|signature| SignedDelegation {
            delegation: Delegation {
                pubkey: session_key,
                expiration,
                targets: None,
            },
            signature: ByteBuf::from(signature),
        })
    })
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
fn create_certified_signature(certificate: Vec<u8>, tree: HashTree) -> Result<Vec<u8>, String> {
    let certificate_signature = CertificateSignature {
        certificate: ByteBuf::from(certificate),
        tree,
    };

    cbor_serialize(&certificate_signature)
}

/// Serializes the given data using CBOR.
fn cbor_serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, String> {
    let mut cbor_serializer = serde_cbor::ser::Serializer::new(Vec::new());
    cbor_serializer.self_describe().map_err(|e| e.to_string())?;
    data.serialize(&mut cbor_serializer)
        .map_err(|e| e.to_string())?;

    Ok(cbor_serializer.into_inner())
}

fn get_signature(
    asset_hashes: &AssetHashes,
    signature_map: &SignatureMap,
    session_key: ByteBuf,
    seed: Hash,
    expiration: u64,
) -> Result<Vec<u8>, String> {
    let certificate =
        data_certificate().ok_or("get_signature must be called using a QUERY call")?;

    let delegation_hash = delegation_hash(&Delegation {
        pubkey: session_key.clone(),
        expiration,
        targets: None,
    });

    let tree = handle_witness(signature_map, seed, delegation_hash, asset_hashes);

    create_certified_signature(certificate, tree)
}

// fn get_signature(
//     asset_hashes: &AssetHashes,
//     signature_map: &SignatureMap,
//     session_key: ByteBuf,
//     seed: Hash,
//     expiration: u64,
// ) -> Result<Vec<u8>, String> {
//     let certificate =
//         data_certificate().ok_or("get_signature must be called using a QUERY call")?;

//     let delegation_hash = delegation_signature_msg_hash(&Delegation {
//         pubkey: session_key.clone(),
//         expiration,
//         targets: None,
//     });

//     let witness = signature_map
//         .witness(hash::hash_bytes(seed), delegation_hash)
//         .ok_or("Signature not found.")?;
//     let witness_hash = witness.reconstruct();
//     let root_hash = signature_map.root_hash();
//     if witness_hash != root_hash {
//         trap(&format!(
//             "Internal error: signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
//             hex::encode(&witness_hash),
//             hex::encode(&root_hash)
//         ));
//     }

//     let tree = ic_certified_map::fork(
//         HashTree::Pruned(ic_certified_map::labeled_hash(
//             LABEL_ASSETS,
//             &asset_hashes.root_hash(),
//         )),
//         ic_certified_map::labeled(&LABEL_SIG[..], witness),
//     );

//     let certificate_signature = CertificateSignature {
//         certificate: ByteBuf::from(certificate),
//         tree,
//     };

//     let mut cbor_serializer = serde_cbor::ser::Serializer::new(Vec::new());
//     cbor_serializer.self_describe().map_err(|e| e.to_string())?;
//     certificate_signature
//         .serialize(&mut cbor_serializer)
//         .map_err(|e| e.to_string())?;
//     Ok(cbor_serializer.into_inner())
// }
