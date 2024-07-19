use candid::Principal;
use ic_cdk::update;
use ic_siwe::{
    eth::{EthAddress, EthSignature},
    login::LoginDetails,
};
use ic_stable_structures::storable::Blob;
use serde_bytes::ByteBuf;

use crate::{update_root_hash, ADDRESS_PRINCIPAL, PRINCIPAL_ADDRESS, SETTINGS, STATE};

/// Authenticates the user by verifying the signature of the SIWE message. This function also
/// prepares the delegation to be fetched in the next step, the `siwe_get_delegation` function.
///
/// # Arguments
/// * `signature` (String): The signature of the SIWE message.
/// * `address` (String): The Ethereum address of the user.
/// * `session_key` (ByteBuf): A unique key that identifies the session.
/// * `nonce` (String): The nonce generated during the `prepare_login` call.
///
/// # Returns
/// * `Ok(LoginOkResponse)`: Contains the user canister public key and other login response data if the login is successful.
/// * `Err(String)`: An error message if the login process fails.
#[update]
fn siwe_login(
    signature: String,
    address: String,
    session_key: ByteBuf,
    nonce: String,
) -> Result<LoginDetails, String> {
    STATE.with(|state| {
        let signature_map = &mut *state.signature_map.borrow_mut();

        // Create an EthAddress from the string. This validates the address.
        let address = EthAddress::new(&address)?;

        // Create an EthSignature from the string. This validates the signature.
        let signature = EthSignature::new(&signature)?;

        // Attempt to log in with the provided signature, address, and session key.
        let login_response = ic_siwe::login::login(
            &signature,
            &address,
            session_key,
            &mut *signature_map,
            &ic_cdk::api::id(),
            &nonce,
        )
        .map_err(|e| e.to_string())?;

        // Update the certified data of the canister due to changes in the signature map.
        update_root_hash(&state.asset_hashes.borrow(), signature_map);

        // Convert the user canister public key to a principal.
        let principal: Blob<29> =
            Principal::self_authenticating(&login_response.user_canister_pubkey).as_slice()[..29]
                .try_into()
                .map_err(|_| format!("Invalid principal: {:?}", login_response))?;

        // Store the mapping of principal to Ethereum address and vice versa if the settings allow it.
        manage_principal_address_mappings(&principal, &address);

        Ok(login_response)
    })
}

fn manage_principal_address_mappings(principal: &Blob<29>, address: &EthAddress) {
    SETTINGS.with(|s| {
        if !s.borrow().disable_principal_to_eth_mapping {
            PRINCIPAL_ADDRESS.with(|pa| {
                pa.borrow_mut().insert(*principal, address.as_byte_array());
            });
        }
        if !s.borrow().disable_eth_to_principal_mapping {
            ADDRESS_PRINCIPAL.with(|ap| {
                ap.borrow_mut().insert(address.as_byte_array(), *principal);
            });
        }
    });
}
