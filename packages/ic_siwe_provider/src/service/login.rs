use candid::Principal;
use ic_cdk::update;
use ic_siwe::{eth::eth_address_to_bytes, login::LoginOkResponse};
use ic_stable_structures::storable::Blob;
use serde_bytes::ByteBuf;

use crate::{update_root_hash, ADDRESS_PRINCIPAL, PRINCIPAL_ADDRESS, STATE};

// Login the user by verifying the signature of the SIWE message. If the signature is valid, the
// public key is returned. In this step, the delegation is also prepared to be fetched in the next
// step.
#[update]
fn login(
    signature: String,
    address: String,
    session_key: ByteBuf,
) -> Result<LoginOkResponse, String> {
    STATE.with(|state| {
        let signature_map = &mut *state.signature_map.borrow_mut();

        match ic_siwe::login::login(&signature, &address, session_key, signature_map) {
            Ok(login_response) => {
                // The login process changes the signature map, so we need to update the certified data
                // of the canister.
                update_root_hash(&state.asset_hashes.borrow(), signature_map);

                let principal: Blob<29> =
                    Principal::self_authenticating(&login_response.user_canister_pubkey).as_slice()
                        [..29]
                        .try_into()
                        .map_err(|_| format!("Invalid principal: {:?}", login_response))?;

                let address: [u8; 20] = eth_address_to_bytes(&address)
                    .map_err(|_| format!("Invalid Ethereum address: {}", address))?
                    .try_into()
                    .map_err(|_| format!("Invalid Ethereum address: {}", address))?;

                PRINCIPAL_ADDRESS.with_borrow_mut(|pa| {
                    pa.insert(principal, address);
                });

                ADDRESS_PRINCIPAL.with_borrow_mut(|ap| {
                    ap.insert(address, principal);
                });

                Ok(login_response)
            }
            Err(e) => Err(e.to_string()),
        }
    })
}
