use candid::CandidType;
use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::{
    delegation::{
        calculate_seed, der_encode_canister_sig_key, get_signature, prepare_delegation,
        DelegationCandidType, SignedDelegationCandidType,
    },
    eth::{
        eth_address_to_bytes, recover_eth_address, validate_eth_address, validate_eth_signature,
    },
    settings::Settings,
    siwe::{
        add_siwe_message, create_siwe_message, get_siwe_message, prune_expired_siwe_messages,
        remove_siwe_message, SiweMessage,
    },
    with_settings, STATE,
};

pub fn prepare_login(address: &str) -> Result<SiweMessage, String> {
    validate_eth_address(address)?;

    let message = create_siwe_message(address)?;

    // Save the SIWE message for use in the login call
    let address = eth_address_to_bytes(address)?;
    add_siwe_message(message.clone(), address);

    Ok(message)
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LoginOkResponse {
    pub expiration: u64,
    pub user_canister_pubkey: ByteBuf,
}

pub fn login(
    signature: &str,
    address: &str,
    session_key: ByteBuf,
) -> Result<LoginOkResponse, String> {
    validate_eth_signature(signature)?;
    validate_eth_address(address)?;

    // Remove expired SIWE messages from the state before proceeding
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
    let seed = calculate_seed(address);

    // Prepare the delegation by adding the signature to the state and updating the root hash of the
    // certificate tree.
    prepare_delegation(seed, session_key, expiration);

    // Create the user canister public key from the seed. From this key, the client can derive the
    // user principal.
    let user_canister_pubkey = ByteBuf::from(der_encode_canister_sig_key(seed.to_vec()));

    Ok(LoginOkResponse {
        expiration,
        user_canister_pubkey,
    })
}

pub fn get_delegation(
    address: &str,
    session_key: ByteBuf,
    expiration: u64,
) -> Result<SignedDelegationCandidType, String> {
    validate_eth_address(address)?;

    let seed = calculate_seed(address);

    with_settings!(|settings: &Settings| {
        STATE.with(|state| {
            get_signature(
                &state.asset_hashes.borrow(),
                &state.sigs.borrow(),
                session_key.clone(),
                seed,
                expiration,
            )
            .map(|signature| SignedDelegationCandidType {
                delegation: DelegationCandidType {
                    pubkey: session_key,
                    expiration,
                    targets: settings.targets.clone(),
                },
                signature: ByteBuf::from(signature),
            })
        })
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
    fn test_create_message_no_settings() {
        let result = prepare_login(VALID_ADDRESS);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Settings are not initialized");
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

    // #[test]
    // fn test_create_message_as_erc_4361() {
    //     init();

    //     let result = create_message_as_erc_4361(VALID_ADDRESS);
    //     assert!(result.is_ok());

    //     // Parse the ERC-4361 message and assert it is ok
    //     let message_result: Result<Message, _> = result.unwrap().parse();
    //     assert!(message_result.is_ok(), "Parsing the message should succeed");
    // }
}
