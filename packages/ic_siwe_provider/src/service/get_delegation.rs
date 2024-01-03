use ic_cdk::{api::data_certificate, query};
use ic_certified_map::{fork, labeled_hash, AsHashTree, HashTree};
use ic_siwe::delegation::{
    create_certified_signature, create_delegation, create_delegation_hash, generate_seed, witness,
    SignedDelegation,
};
use serde_bytes::ByteBuf;

use crate::{LABEL_ASSETS, LABEL_SIG, STATE};

// Once logged in, the user can fetch the delegation to be used for authentication.
#[query]
fn get_delegation(
    address: String,
    session_key: ByteBuf,
    expiration: u64,
) -> Result<SignedDelegation, String> {
    let certificate = data_certificate().expect("get_delegation must be called using a query call");

    STATE.with(|s| {
        let signature_map = s.signature_map.borrow_mut();
        let seed = generate_seed(&address);

        let delegation = create_delegation(session_key, expiration);
        let delegation_hash = create_delegation_hash(&delegation);
        let signature_witness = witness(&signature_map, seed, delegation_hash)?;

        // Create a forked version of the state tree with the signature witness and the pruned asset hashes.
        let tree = fork(
            HashTree::Pruned(labeled_hash(
                LABEL_ASSETS,
                &s.asset_hashes.borrow().root_hash(),
            )),
            ic_certified_map::labeled(LABEL_SIG, signature_witness),
        );

        // The canister certifies that the delegation is valid.
        let signature = create_certified_signature(certificate, tree)?;

        Ok(SignedDelegation {
            delegation,
            signature: ByteBuf::from(signature),
        })
    })
}
