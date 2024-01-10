use candid::Principal;
use ic_cdk::update;
use ic_siwe::{eth::eth_address_to_bytes, login::LoginOkResponse};
use ic_stable_structures::storable::Blob;
use serde_bytes::ByteBuf;

use crate::{update_root_hash, ADDRESS_PRINCIPAL, PRINCIPAL_ADDRESS, STATE};

/// Authenticates the user by verifying the signature of the SIWE message. This function also
/// prepares the delegation to be fetched in the next step, the `get_delegation` function.
///
/// # Arguments
/// * `signature` (String): The signature of the SIWE message.
/// * `address` (String): The Ethereum address of the user.
/// * `session_key` (ByteBuf): A unique key that identifies the session.
///
/// # Returns
/// * `Ok(LoginOkResponse)`: Contains the user canister public key and other login response data if the login is successful.
/// * `Err(String)`: An error message if the login process fails.
#[update]
fn login(
    signature: String,
    address: String,
    session_key: ByteBuf,
) -> Result<LoginOkResponse, String> {
    STATE.with(|state| {
        let signature_map = &mut *state.signature_map.borrow_mut();

        // Attempt to log in with the provided signature, address, and session key.
        match ic_siwe::login::login(&signature, &address, session_key, signature_map) {
            Ok(login_response) => {
                // Update the certified data of the canister due to changes in the signature map.
                update_root_hash(&state.asset_hashes.borrow(), signature_map);

                // Convert the user canister public key to a principal.
                let principal: Blob<29> =
                    Principal::self_authenticating(&login_response.user_canister_pubkey).as_slice()
                        [..29]
                        .try_into()
                        .map_err(|_| format!("Invalid principal: {:?}", login_response))?;

                // Convert the Ethereum address to a byte array.
                let address_bytes: [u8; 20] = eth_address_to_bytes(&address)
                    .map_err(|_| format!("Invalid Ethereum address: {}", address))?
                    .try_into()
                    .map_err(|_| format!("Invalid Ethereum address: {}", address))?;

                // Store the mapping of principal to Ethereum address and vice versa.
                PRINCIPAL_ADDRESS.with_borrow_mut(|pa| {
                    pa.insert(principal, address_bytes);
                });
                ADDRESS_PRINCIPAL.with_borrow_mut(|ap| {
                    ap.insert(address_bytes, principal);
                });

                Ok(login_response)
            }
            Err(e) => Err(e.to_string()),
        }
    })
}
