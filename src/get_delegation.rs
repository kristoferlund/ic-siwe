use crate::{
    types::{
        delegation::{Delegation, SignedDelegation},
        settings::get_settings,
        signature_map::SignatureMap,
        state::AssetHashes,
    },
    utils::{
        delegation::{calculate_seed, delegation_signature_msg_hash, LABEL_ASSETS, LABEL_SIG},
        eth::validate_address,
        hash,
        siwe::get_siwe_message,
    },
    STATE,
};
use ic_cdk::{api::data_certificate, trap};
use ic_certified_map::{AsHashTree, Hash, HashTree};
use serde::Serialize;
use serde_bytes::ByteBuf;

#[derive(Serialize)]
struct Sig<'a> {
    certificate: ByteBuf,
    tree: HashTree<'a>,
}

pub fn get_delegation(address: &str, session_key: &str) -> Result<SignedDelegation, String> {
    validate_address(address)?;
    if session_key.len() != 64 {
        return Err(String::from("Invalid session key length"));
    }

    let message = get_siwe_message(&address)?;
    let settings = get_settings()?;
    let expiration = message.issued_at + settings.session_expires_in;

    // trap_if_not_authenticated(entries.iter().map(|e| &e.pubkey));
    let session_key: ByteBuf = ByteBuf::from(session_key);

    STATE.with(|state| {
        match get_signature(
            &state.asset_hashes.borrow(),
            &state.sigs.borrow(),
            session_key.clone(),
            calculate_seed(address),
            expiration,
        ) {
            Ok(signature) => {
                // Remove the now used SIWE message
                state.siwe_messages.borrow_mut().remove(address.as_bytes());

                Ok(SignedDelegation {
                    delegation: Delegation {
                        pubkey: session_key,
                        expiration,
                        targets: None,
                    },
                    signature: ByteBuf::from(signature),
                })
            }
            Err(err) => Err(err),
        }
    })
}

fn get_signature(
    asset_hashes: &AssetHashes,
    sigs: &SignatureMap,
    pk: ByteBuf,
    seed: Hash,
    expiration: u64,
) -> Result<Vec<u8>, String> {
    let certificate =
        data_certificate().ok_or("get_signature must be called using a QUERY call")?;

    let msg_hash = delegation_signature_msg_hash(&Delegation {
        pubkey: pk,
        expiration,
        targets: None,
    });

    let witness = sigs
        .witness(hash::hash_bytes(seed), msg_hash)
        .ok_or("Signature not found.")?;
    let witness_hash = witness.reconstruct();
    let root_hash = sigs.root_hash();
    if witness_hash != root_hash {
        trap(&format!(
          "internal error: signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
          hex::encode(&witness_hash),
          hex::encode(&root_hash)
      ));
    }

    let tree = ic_certified_map::fork(
        HashTree::Pruned(ic_certified_map::labeled_hash(
            LABEL_ASSETS,
            &asset_hashes.root_hash(),
        )),
        ic_certified_map::labeled(&LABEL_SIG[..], witness),
    );

    let sig = Sig {
        certificate: ByteBuf::from(certificate),
        tree,
    };

    let mut cbor = serde_cbor::ser::Serializer::new(Vec::new());
    cbor.self_describe().unwrap();
    sig.serialize(&mut cbor).unwrap();
    Ok(cbor.into_inner())
}
