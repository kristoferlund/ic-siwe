use ic_cdk::{api::data_certificate, query};
use ic_certified_map::{fork, labeled_hash, AsHashTree, HashTree};
use ic_siwe::{
    delegation::{
        create_certified_signature, create_delegation, create_delegation_hash, generate_seed,
        witness, SignedDelegation,
    },
    eth::EthAddress,
};
use serde_bytes::ByteBuf;

use crate::{LABEL_ASSETS, LABEL_SIG, STATE};

/// Retrieves a signed delegation for a user to authenticate further actions.
///
/// # Arguments
/// * `address` (String): The Ethereum address of the user.
/// * `session_key` (ByteBuf): A unique key that identifies the session.
/// * `expiration` (u64): The expiration time of the delegation in nanoseconds since the UNIX epoch.
///
/// # Returns
/// * `Ok(SignedDelegation)`: A signed delegation containing the session key, expiration, and targets if successful.
/// * `Err(String)`: An error message if there is a failure in creating or certifying the delegation.
#[query]
fn siwe_get_delegation(
    address: String,
    session_key: ByteBuf,
    expiration: u64,
) -> Result<SignedDelegation, String> {
    // Fetches the certificate for the current call, required for creating a certified signature.
    let certificate =
        data_certificate().expect("siwe_get_delegation must be called using a query call");

    // Create an EthAddress from the string. This validates the address.
    let address = EthAddress::new(&address)?;

    STATE.with(|s| {
        let signature_map = s.signature_map.borrow_mut();

        // Generate a unique seed based on the user's Ethereum address.
        let seed = generate_seed(&address);

        // Create a delegation object with the session key and expiration.
        let delegation = create_delegation(session_key, expiration)?;

        // Hash the delegation for signing.
        let delegation_hash = create_delegation_hash(&delegation);

        // Create a witness of the signature, confirming the delegation's presence in the signature map.
        let signature_witness = witness(&signature_map, seed, delegation_hash)?;

        // Create a forked version of the state tree with the signature witness and the pruned asset hashes.
        let tree = fork(
            HashTree::Pruned(labeled_hash(
                LABEL_ASSETS,
                &s.asset_hashes.borrow().root_hash(),
            )),
            ic_certified_map::labeled(LABEL_SIG, signature_witness),
        );

        // Certify that the delegation is valid by creating a signature.
        let signature = create_certified_signature(certificate, tree)?;

        Ok(SignedDelegation {
            delegation,
            signature: ByteBuf::from(signature),
        })
    })
}
