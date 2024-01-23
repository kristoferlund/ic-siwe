use candid::CandidType;
use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::{
    delegation::{
        create_delegation, create_delegation_hash, create_user_canister_pubkey, generate_seed,
    },
    eth::{
        eth_address_to_bytes, recover_eth_address, validate_eth_address, validate_eth_signature,
    },
    hash,
    settings::Settings,
    signature_map::SignatureMap,
    siwe::{
        add_siwe_message, get_siwe_message, prune_expired_siwe_messages, remove_siwe_message,
        SiweMessage,
    },
    time::get_current_time,
    with_settings,
};

const MAX_SIGS_TO_PRUNE: usize = 10;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LoginOkResponse {
    pub expiration: u64,
    pub user_canister_pubkey: ByteBuf,
}

/// This function is the first step of the user login process. It validates the provided Ethereum address,
/// creates a SIWE message, saves it for future use, and returns it.
///
/// # Parameters
/// * `address`: A string slice (`&str`) representing the user's Ethereum address. This address is
///   validated and used to create the SIWE message.
///
/// # Returns
/// A `Result` that, on success, contains the `SiweMessage` for the user, or an error string on failure.
pub fn prepare_login(address: &str) -> Result<SiweMessage, String> {
    validate_eth_address(address)?;

    let message = SiweMessage::new(address)?;

    // Save the SIWE message for use in the login call
    let address = eth_address_to_bytes(address)?;
    add_siwe_message(message.clone(), address);

    Ok(message)
}

/// Handles the second step of the user login process. It verifies the signature against the SIWE message,
/// creates a delegation for the session, adds it to the signature map, and returns login response information.
///
/// # Parameters
/// * `signature`: The SIWE message signature to verify.
/// * `address`: The Ethereum address used to sign the SIWE message.
/// * `session_key`: A unique session key to be used for the delegation.
/// * `signature_map`: A mutable reference to `SignatureMap` to which the delegation hash will be added
///   after successful validation.
///
/// # Returns
/// A `Result` that, on success, contains the `LoginOkResponse` with session expiration and user canister
/// public key, or an error string on failure.
pub fn login(
    signature: &str,
    address: &str,
    session_key: ByteBuf,
    signature_map: &mut SignatureMap,
) -> Result<LoginOkResponse, String> {
    validate_eth_signature(signature)?;
    validate_eth_address(address)?;

    // Remove expired SIWE messages from the state before proceeding. The init settings determines
    // the time to live for SIWE messages.
    prune_expired_siwe_messages();

    // Get the previously created SIWE message for current address. If it has expired or does not
    // exist, return an error.
    let address_bytes = eth_address_to_bytes(address)?;
    let message = get_siwe_message(&address_bytes)?;
    let message_string: String = message.clone().into();

    // Verify the supplied signature against the SIWE message and recover the Ethereum address
    // used to sign the message.
    let recovered_address = recover_eth_address(&message_string, signature)?;
    if recovered_address != address {
        return Err(String::from("Signature verification failed"));
    }

    // At this point, the signature has been verified and the SIWE message has been used. Remove
    // the SIWE message from the state.
    remove_siwe_message(&address_bytes);

    // The delegation is valid for the duration of the session as defined in the settings.
    let expiration = with_settings!(|settings: &Settings| {
        message
            .issued_at
            .saturating_add(settings.session_expires_in)
    });

    // The seed is what uniquely identifies the delegation. It is derived from the salt, the
    // Ethereum address and the SIWE message URI.
    let seed = generate_seed(address);

    // Before adding the signature to the signature map, prune any expired signatures.
    signature_map.prune_expired(get_current_time(), MAX_SIGS_TO_PRUNE);

    // Create the delegation and add its hash to the signature map. The seed is used as the map key.
    let delegation = create_delegation(session_key, expiration);
    let delegation_hash = create_delegation_hash(&delegation);
    signature_map.put(hash::hash_bytes(seed), delegation_hash);

    // Create the user canister public key from the seed. From this key, the client can derive the
    // user principal.
    let user_canister_pubkey = ByteBuf::from(create_user_canister_pubkey(seed.to_vec()));

    Ok(LoginOkResponse {
        expiration,
        user_canister_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use crate::{settings::SettingsBuilder, SETTINGS};

    use super::*;

    const VALID_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    fn init() {
        let settings = SettingsBuilder::new("localhost", "http://localhost:8080", "salt")
            .scheme("http")
            .statement("Login to the app")
            .build()
            .unwrap();

        SETTINGS.with(|s| {
            *s.borrow_mut() = Some(settings);
        });
    }

    #[test]
    fn test_create_message_success() {
        init();

        let result = prepare_login(VALID_ADDRESS);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_message_invalid_address() {
        init();

        let invalid_address = "0xG".to_owned() + &"1".repeat(39); // A mock invalid Ethereum address
        let result = prepare_login(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Hex decoding failed"
        );
    }

    #[test]
    fn test_create_message_invalid_hex_encoding() {
        init();

        let invalid_address = "0x".to_owned() + &"G".repeat(40); // Invalid hex
        let result = prepare_login(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Hex decoding failed"
        );
    }

    #[test]
    fn test_create_message_address_too_short() {
        init();

        let invalid_address = "0x".to_owned() + &"1".repeat(39); // Too short
        let result = prepare_login(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long"
        );
    }

    #[test]
    fn test_create_message_address_too_long() {
        init();

        let invalid_address = "0x".to_owned() + &"1".repeat(41); // Too long
        let result = prepare_login(invalid_address.as_str());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long"
        );
    }

    #[test]
    fn test_create_message_expected_message() {
        init();

        let result = prepare_login(VALID_ADDRESS).expect("Should succeed with valid address");

        with_settings!(|settings: &Settings| {
            assert_eq!(result.address, VALID_ADDRESS);
            assert_eq!(result.scheme, settings.scheme);
            assert_eq!(result.domain, settings.domain);
            assert_eq!(result.statement, settings.statement);
            assert_eq!(result.uri, settings.uri);
            assert_eq!(result.version, 1);
            assert_eq!(result.chain_id, settings.chain_id);
        });
    }
}
