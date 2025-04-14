mod common;

use candid::{encode_args, encode_one, Principal};
use common::{
    create_canister, create_session_identity, create_wallet, full_login, init, query, update,
    valid_settings, PrepareLoginOkResponse, RuntimeFeature, NONCE, SESSION_KEY, VALID_ADDRESS,
};
use ic_agent::Identity;
use ic_siwe::{delegation::SignedDelegation, login::LoginDetails};
use pocket_ic::PocketIc;
use serde_bytes::ByteBuf;
use siwe::Message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::common::{prepare_login_and_sign_message, SettingsInput};

#[test]
#[should_panic]
fn test_init_with_no_settings() {
    let ic = PocketIc::new();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    let sender = None;
    // Empty init argument, should cause a panic
    ic.install_canister(canister_id, wasm_module, encode_one(()).unwrap(), sender);
}

#[test]
fn test_init_with_valid_settings() {
    let ic = PocketIc::new();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    let settings = valid_settings(canister_id, None);
    let arg = encode_one(settings).unwrap();
    let sender = None;
    ic.install_canister(canister_id, wasm_module, arg, sender);
}

#[test]
#[should_panic]
fn test_init_with_invalid_settings() {
    let ic = PocketIc::new();
    let (canister_id, wasm_module) = common::create_canister(&ic);
    let mut settings = valid_settings(canister_id, None);
    settings.domain = "invalid domain".to_string(); // Invalid domain, should cause a panic
    let arg = encode_one(settings).unwrap();
    let sender = None;
    ic.install_canister(canister_id, wasm_module, arg, sender);
}

#[test]
fn test_upgrade_with_changed_arguments() {
    let ic = PocketIc::new();

    // First, install
    let (ic_siwe_provider_canister, _) = init(&ic, None);

    // Then, upgrade
    let wasm_path: std::ffi::OsString =
        std::env::var_os("IC_SIWE_PROVIDER_PATH").expect("Missing ic_siwe_provider wasm file");
    let wasm_module = std::fs::read(wasm_path).unwrap();
    let targets: Option<Vec<Principal>> = Some(vec![ic_siwe_provider_canister]);
    let settings = SettingsInput {
        domain: "192.168.0.1".to_string(),
        uri: "http://192.168.0.1:666".to_string(),
        salt: "another-salt".to_string(),
        chain_id: Some(666),
        scheme: Some("https".to_string()),
        statement: Some("Some login statement".to_string()),
        sign_in_expires_in: Some(Duration::from_secs(300).as_nanos() as u64), // 5 minutes
        session_expires_in: Some(Duration::from_secs(60 * 60 * 24 * 14).as_nanos() as u64), // 2 weeks
        targets: targets.clone(),
        runtime_features: None,
    };
    let arg = encode_one(settings).unwrap();
    let sender = None;
    let upgrade_result =
        ic.upgrade_canister(ic_siwe_provider_canister, wasm_module, arg.clone(), sender);
    assert!(upgrade_result.is_ok());

    // Fast forward in time to allow the ic_siwe_provider_canister to be fully installed.
    for _ in 0..5 {
        ic.tick();
    }

    // Call siwe_prepare_login, check that new settings are reflected in returned siwe_message
    let address = encode_one(VALID_ADDRESS).unwrap();
    let response: Result<PrepareLoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_prepare_login",
        address,
    );
    assert!(response.is_ok());
    let prepare_login_ok_response: PrepareLoginOkResponse = response.unwrap();
    let siwe_message: Message = prepare_login_ok_response.siwe_message.parse().unwrap();
    assert_eq!(siwe_message.domain, "192.168.0.1");
    assert_eq!(siwe_message.uri, "http://192.168.0.1:666");
    assert_eq!(siwe_message.chain_id, 666);
    assert_eq!(
        siwe_message.statement,
        Some(String::from("Some login statement"))
    );
}

#[test]
fn test_upgrade_with_no_settings() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let wasm_path: std::ffi::OsString =
        std::env::var_os("IC_SIWE_PROVIDER_PATH").expect("Missing ic_siwe_provider wasm file");
    let wasm_module = std::fs::read(wasm_path).unwrap();
    let sender = None;
    let result = ic.upgrade_canister(
        ic_siwe_provider_canister,
        wasm_module,
        encode_one(()).unwrap(),
        sender,
    );
    assert!(result.is_err());
}

#[test]
fn test_siwe_prepare_login_invalid_address() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let address = encode_one("invalid address").unwrap();
    let response: Result<String, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_prepare_login",
        address,
    );
    assert_eq!(
        response.unwrap_err(),
        "Address format error: Must start with '0x' and be 42 characters long"
    );
}

#[test]
fn test_siwe_prepare_login_not_eip55_address() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let address = encode_one("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
    let response: Result<String, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_prepare_login",
        address,
    );
    assert_eq!(response.unwrap_err(), "EIP-55 error: Not EIP-55 encoded");
}

#[test]
fn test_siwe_prepare_login_ok() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let address = encode_one(VALID_ADDRESS).unwrap();
    let response: Result<PrepareLoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_prepare_login",
        address,
    );
    assert!(response.is_ok());
    let prepare_login_ok_response: PrepareLoginOkResponse = response.unwrap();
    let siwe_message: Message = prepare_login_ok_response.siwe_message.parse().unwrap();
    assert_eq!(
        siwe_message.address,
        hex::decode(&VALID_ADDRESS[2..]).unwrap().as_slice()
    );
    assert!(!prepare_login_ok_response.nonce.is_empty());
}

#[test]
fn test_login_signature_too_short() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let signature = "0xTOO-SHORT";
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY, NONCE)).unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args,
    );
    assert_eq!(
        response.unwrap_err(),
        "Signature format error: Must start with '0x' and be 132 characters long"
    );
}

#[test]
fn test_login_signature_too_long() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let signature = "0xÖÖ809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809800000-TOO-LONG";
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY, NONCE)).unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args,
    );
    assert_eq!(
        response.unwrap_err(),
        "Signature format error: Must start with '0x' and be 132 characters long"
    );
}

#[test]
fn test_incorrect_signature_format() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let signature = "0xÖÖ809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809800000";
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY, NONCE)).unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args,
    );
    assert_eq!(
        response.unwrap_err(),
        "Decoding error: Invalid character 'Ã' at position 0"
    );
}

// Generated SIWE messages are only valid for a set amount of time. Fast forward in time to make the message expire.
#[test]
fn test_sign_in_message_expired() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let (wallet, address) = create_wallet();
    let (signature, _) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);

    ic.advance_time(Duration::from_secs(10));

    let args = encode_args((signature, address, SESSION_KEY, NONCE)).unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args,
    );
    assert_eq!(response.unwrap_err(), "Message not found");
}

// A valid signature but with a different address
#[test]
fn test_sign_in_address_mismatch() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let (wallet, address) = create_wallet();
    let (signature, _) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY, NONCE)).unwrap(); // Wrong address
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args,
    );
    assert_eq!(response.unwrap_err(), "Message not found");
}

// A manilulated signature with the correct address
#[test]
fn test_sign_in_signature_manipulated() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let (wallet, address) = create_wallet();
    let (signature, prepare_login_ok_response) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let manipulated_signature = format!("{}0000000000", &signature[..signature.len() - 10]);
    let args = encode_args((
        manipulated_signature,
        address,
        SESSION_KEY,
        prepare_login_ok_response.nonce,
    ))
    .unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args,
    );
    assert_eq!(response.unwrap_err(), "Recovered address does not match");
}

#[test]
fn test_sign_in_ok() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let (wallet, address) = create_wallet();
    let (signature, prepare_login_ok_response) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let args = encode_args((
        signature,
        address,
        SESSION_KEY,
        prepare_login_ok_response.nonce,
    ))
    .unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args,
    );
    assert!(response.is_ok());
    assert!(response.unwrap().user_canister_pubkey.len() == 62);
}

// Use the same signature twice. This should fail because the message is already used.
#[test]
fn test_sign_in_replay_attack() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);
    let (wallet, address) = create_wallet();
    let (signature, prepare_login_ok_response) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let args = encode_args((
        signature,
        address,
        SESSION_KEY,
        prepare_login_ok_response.nonce,
    ))
    .unwrap();
    let response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args.clone(),
    );
    assert!(response.is_ok());
    let second_response: Result<LoginDetails, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        args,
    );
    assert_eq!(second_response.unwrap_err(), "Message not found");
}

#[test]
fn test_sign_in_siwe_get_delegation() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init(&ic, None);
    let (_, _) = full_login(&ic, ic_siwe_provider_canister, targets);
}

// After login, the delegation needs to be fetched before the delegation signature expires. Fast forward in time to make
// the delegation signature expire.
#[test]
fn test_sign_in_siwe_get_delegation_timeout() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);

    // Create wallet and session identity
    let (wallet1, address1) = create_wallet();
    let (signature, prepare_login_ok_response) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet1, &address1);
    let session_identity = create_session_identity();
    let session_pubkey = session_identity.public_key().unwrap();

    // Login
    let login_args = encode_args((
        signature,
        address1.clone(),
        session_pubkey.clone(),
        prepare_login_ok_response.nonce.clone(),
    ))
    .unwrap();
    let login_response: LoginDetails = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        login_args,
    )
    .unwrap();

    // Fast forward in time to make the delegation signature expire. Exired signatures are pruned every time
    // login is called.
    ic.advance_time(Duration::from_secs(100));

    // Create another wallet and session identity
    let (wallet2, address2) = create_wallet();
    let (signature2, prepare_login_ok_response) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet2, &address2);
    let session_identity2 = create_session_identity();
    let session_pubkey2 = session_identity2.public_key().unwrap();

    // Login address 2, this should cause the delegation signature for address 1 to be pruned
    let login_args2 = encode_args((
        signature2,
        address2.clone(),
        session_pubkey2.clone(),
        prepare_login_ok_response.nonce.clone(),
    ))
    .unwrap();
    let _: LoginDetails = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        login_args2,
    )
    .unwrap();

    // Get the delegation for address 1, this should fail because the delegation signature has been pruned
    let siwe_get_delegation_args = encode_args((
        address1.clone(),
        session_pubkey.clone(),
        login_response.expiration,
    ))
    .unwrap();
    let siwe_get_delegation_response: Result<SignedDelegation, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_get_delegation",
        siwe_get_delegation_args,
    );

    assert!(siwe_get_delegation_response.is_err());
}

// Get a delegation, using an expiration value that is not the one returned by siwe_login, should
// fail
#[test]
fn test_sign_in_siwe_get_delegation_invalid_expiration() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);

    // Create wallet and session identity
    let (wallet, address) = create_wallet();
    let (signature, prepare_login_ok_response) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let session_identity = create_session_identity();
    let session_pubkey = session_identity.public_key().unwrap();

    // Login
    let login_args = encode_args((
        signature,
        address.clone(),
        session_pubkey.clone(),
        prepare_login_ok_response.nonce.clone(),
    ))
    .unwrap();
    let _: LoginDetails = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        login_args,
    )
    .unwrap();

    let wrong_expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let expiration = wrong_expiration + 1000 * 60 * 60 * 24 * 7; // 1 week

    let siwe_get_delegation_args =
        encode_args((address.clone(), session_pubkey.clone(), expiration)).unwrap();
    let siwe_get_delegation_response: Result<SignedDelegation, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_get_delegation",
        siwe_get_delegation_args,
    );

    assert!(siwe_get_delegation_response.is_err());
    let error_msg = siwe_get_delegation_response.unwrap_err();
    assert_eq!(error_msg, "Signature not found");
}

// Get a delegation, using a session key that is not the one returned by siwe_login, should
// fail
#[test]
fn test_sign_in_siwe_get_delegation_invalid_session_pubkey() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, _) = init(&ic, None);

    // Create wallet and session identity
    let (wallet, address) = create_wallet();
    let (signature, prepare_login_ok_response) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let session_identity = create_session_identity();
    let session_pubkey = session_identity.public_key().unwrap();

    // Login
    let login_args = encode_args((
        signature,
        address.clone(),
        session_pubkey.clone(),
        prepare_login_ok_response.nonce.clone(),
    ))
    .unwrap();
    let login_details: LoginDetails = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
        login_args,
    )
    .unwrap();

    let wrong_session_identity = create_session_identity();
    let wrong_session_pubkey = wrong_session_identity.public_key().unwrap();

    let siwe_get_delegation_args = encode_args((
        address.clone(),
        wrong_session_pubkey,
        login_details.expiration,
    ))
    .unwrap();
    let siwe_get_delegation_response: Result<SignedDelegation, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_get_delegation",
        siwe_get_delegation_args,
    );

    assert!(siwe_get_delegation_response.is_err());
    let error_msg = siwe_get_delegation_response.unwrap_err();
    assert_eq!(error_msg, "Signature not found");
}

#[test]
fn test_get_caller_address() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init(&ic, None);
    let (address, delegated_identity) = full_login(&ic, ic_siwe_provider_canister, targets);
    let caller_address_response: Result<String, String> = query(
        &ic,
        delegated_identity.sender().unwrap(),
        ic_siwe_provider_canister,
        "get_caller_address",
        encode_one(()).unwrap(),
    );
    assert!(caller_address_response.is_ok());
    assert_eq!(caller_address_response.unwrap(), address);
}

#[test]
fn test_get_caller_address_principal_not_logged_in() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init(&ic, None);
    let (_, _) = full_login(&ic, ic_siwe_provider_canister, targets);
    let response: Result<String, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_caller_address",
        encode_one(()).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "No address found for the given principal"
    );
}

#[test]
fn test_get_address() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init(&ic, None);
    let (address, delegated_identity) = full_login(&ic, ic_siwe_provider_canister, targets);
    let response: Result<String, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_address",
        encode_one(delegated_identity.sender().unwrap().as_slice()).unwrap(),
    );
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), address);
}

#[test]
fn test_get_address_not_found() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init(&ic, None);
    let (_, _) = full_login(&ic, ic_siwe_provider_canister, targets);
    let response: Result<String, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_address",
        encode_one(Principal::anonymous().as_slice()).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "No address found for the given principal"
    );
}

#[test]
fn test_get_principal() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init(&ic, None);
    let (address, delegated_identity) = full_login(&ic, ic_siwe_provider_canister, targets);
    let response: Result<ByteBuf, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_principal",
        encode_one(address).unwrap(),
    );
    assert!(response.is_ok());
    assert_eq!(
        response.unwrap(),
        delegated_identity.sender().unwrap().as_slice()
    );
}

#[test]
fn test_get_principal_not_found() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init(&ic, None);
    let (_, _) = full_login(&ic, ic_siwe_provider_canister, targets);
    let response: Result<ByteBuf, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_principal",
        encode_one(VALID_ADDRESS).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "No principal found for the given address"
    );
}

pub fn settings_disable_eth_and_principal_mapping(
    canister_id: Principal,
    targets: Option<Vec<Principal>>,
) -> SettingsInput {
    // If specific targets have been listed, add the canister id of this canister to the list of targets.
    let targets: Option<Vec<Principal>> = match targets {
        Some(targets) => {
            let mut targets = targets;
            targets.push(canister_id);
            Some(targets)
        }
        None => None,
    };

    SettingsInput {
        domain: "127.0.0.1".to_string(),
        uri: "http://127.0.0.1:5173".to_string(),
        salt: "dummy-salt".to_string(),
        chain_id: Some(10),
        scheme: Some("http".to_string()),
        statement: Some("Login to the app".to_string()),
        sign_in_expires_in: Some(Duration::from_secs(3).as_nanos() as u64), // 3 seconds
        session_expires_in: Some(Duration::from_secs(60 * 60 * 24 * 7).as_nanos() as u64), // 1 week
        targets: targets.clone(),
        runtime_features: Some(vec![
            RuntimeFeature::DisableEthToPrincipalMapping,
            RuntimeFeature::DisablePrincipalToEthMapping,
        ]),
    }
}

pub fn init_disable_eth_and_principal_mapping(
    ic: &PocketIc,
    targets: Option<Vec<Principal>>,
) -> (Principal, Option<Vec<Principal>>) {
    let (canister_id, wasm_module) = create_canister(ic);
    let settings = settings_disable_eth_and_principal_mapping(canister_id, targets.clone());
    let arg = encode_one(settings).unwrap();
    let sender = None;

    ic.install_canister(canister_id, wasm_module, arg.clone(), sender);

    // Fast forward in time to allow the ic_siwe_provider_canister to be fully installed.
    for _ in 0..5 {
        ic.tick();
    }

    (canister_id, targets)
}

#[test]
fn test_eth_to_principal_mapping_disabled() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init_disable_eth_and_principal_mapping(&ic, None);
    let (_, _) = full_login(&ic, ic_siwe_provider_canister, targets);
    let response: Result<ByteBuf, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_principal",
        encode_one(VALID_ADDRESS).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "Ethereum address to principal mapping is disabled"
    );
}

#[test]
fn test_principal_to_eth_mapping_disabled() {
    let ic = PocketIc::new();
    let (ic_siwe_provider_canister, targets) = init_disable_eth_and_principal_mapping(&ic, None);
    let (_, delegated_identity) = full_login(&ic, ic_siwe_provider_canister, targets);
    let response: Result<String, String> = query(
        &ic,
        delegated_identity.sender().unwrap(),
        ic_siwe_provider_canister,
        "get_address",
        encode_one(delegated_identity.sender().unwrap().as_slice()).unwrap(),
    );
    assert!(response.is_err());
    assert_eq!(
        response.unwrap_err(),
        "Principal to Ethereum address mapping is disabled"
    );
}

// NOT RUN //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PocketIc does not yet support Delegation targets and expiration

// #[test]
// fn test_session_expired() {
//     let (ic_siwe_provider_canister, _) = init(&ic, None);
//     let (address, delegated_identity) = full_login(&ic, ic_siwe_provider_canister);

//     ic.advance_time(Duration::from_secs(60 * 60 * 24 * 7 + 1));
//     ic.tick();

//     // Use the delegated identity to call the ic_siwe_provider_canister. Caller address should be the same as the
//     // address generated by `create_wallet`.
//     let caller_address_response: Result<String, String> = query(
//         &ic,
//         delegated_identity.sender().unwrap(),
//         ic_siwe_provider_canister,
//         "get_caller_address",
//         encode_one(()).unwrap(),
//     );

//     assert!(caller_address_response.is_err());
//     assert_eq!(caller_address_response.unwrap(), address);
// }

// #[test]
// fn test_call_get_address_from_other_canister() {
//     let ic = PocketIc::new();
//     let test_canister = ic.create_canister();
//     ic.add_cycles(test_canister, 2_000_000_000_000);
//     let (ic_siwe_provider_canister, targets) = init(&ic, Some(vec![test_canister1]));
//     let (address, delegated_identity) = full_login(&ic, ic_siwe_provider_canister, targets);
//     let test_canister_wasm_path: std::ffi::OsString =
//         std::env::var_os("TEST_CANISTER_PATH").expect("Missing test_canister wasm file");
//     let test_canister_wasm_module = std::fs::read(test_canister_wasm_path).unwrap();
//     let sender = None;
//     let arg = encode_one(ic_siwe_provider_canister.to_text()).unwrap();
//     ic.install_canister(test_canister, test_canister_wasm_module, arg, sender);

//     let whoami_response: Result<(String, String), String> = query(
//         &ic,
//         delegated_identity.sender().unwrap(),
//         test_canister,
//         "whoami",
//         encode_one(()).unwrap(),
//     );

//     assert!(whoami_response.is_ok());
//     let whoami_response = whoami_response.unwrap();

//     // The returned principal should be the same as the principal of the delegated identity
//     assert_eq!(
//         whoami_response.0,
//         delegated_identity.sender().unwrap().to_text()
//     );

//     // The returned address should be the same as the address generated by `create_wallet`
//     assert_eq!(whoami_response.1, address);
// }

// #[test]
// fn test_call_get_address_from_other_canister_session_expired() {
//     let (ic_siwe_provider_canister, _) = init(&ic, None);
//     let (_, delegated_identity) = full_login(&ic, ic_siwe_provider_canister);

//     let test_canister = ic.create_canister();
//     ic.add_cycles(test_canister, 2_000_000_000_000);

//     let test_canister_wasm_path: std::ffi::OsString =
//         std::env::var_os("TEST_CANISTER_PATH").expect("Missing test_canister wasm file");
//     let test_canister_wasm_module = std::fs::read(test_canister_wasm_path).unwrap();

//     let sender = None;

//     let arg = encode_one(ic_siwe_provider_canister.to_text()).unwrap();
//     ic.install_canister(test_canister, test_canister_wasm_module, arg, sender);

//     // Advance time to make the session expire
//     ic.advance_time(Duration::from_secs(6000 * 60 * 24 * 8));
//     ic.tick();

//     let whoami_response: Result<(String, String), String> = query(
//         &ic,
//         delegated_identity.sender().unwrap(),
//         test_canister,
//         "whoami",
//         encode_one(()).unwrap(),
//     );

//     println!("{:?}", whoami_response);

//     assert!(whoami_response.is_err());
//     assert_eq!(
//         whoami_response.unwrap_err(),
//         "No principal found for the given address"
//     );
// }
