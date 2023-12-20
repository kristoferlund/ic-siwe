use std::time::Duration;

use candid::{decode_one, encode_args, encode_one, CandidType, Principal};
use ethers::{
    core::k256::ecdsa::SigningKey,
    signers::{LocalWallet, Signer, Wallet},
    utils::{hash_message, to_checksum},
};
use ic_agent::{
    identity::{BasicIdentity, DelegatedIdentity, Delegation, SignedDelegation},
    Identity,
};
use ic_siwe::{delegation::SignedDelegationCandidType, login::LoginOkResponse};
use pocket_ic::{PocketIc, WasmResult};
use rand::Rng;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use siwe::Message;

#[derive(CandidType)]
struct SettingsInput {
    pub domain: String,
    pub uri: String,
    pub salt: String,
    pub chain_id: Option<u32>,
    pub scheme: Option<String>,
    pub statement: Option<String>,
    pub sign_in_expires_in: Option<u64>,
    pub session_expires_in: Option<u64>,
}

const VALID_ADDRESS: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
const SESSION_KEY: &[u8] = b"987687687687687687687687686";

fn init() -> (PocketIc, Principal) {
    let ic = PocketIc::new();

    let canister_id = ic.create_canister();
    ic.add_cycles(canister_id, 2_000_000_000_000);

    let wasm_path: std::ffi::OsString =
        std::env::var_os("IC_SIWE_PROVIDER_PATH").expect("Missing ic_siwe_provider wasm file");
    let wasm_module = std::fs::read(wasm_path).unwrap();

    let settings = SettingsInput {
        domain: "127.0.0.1".to_string(),
        uri: "http://127.0.0.1:5173".to_string(),
        salt: "dummy salt".to_string(),
        chain_id: Some(10),
        scheme: Some("http".to_string()),
        statement: Some("Login to the app".to_string()),
        sign_in_expires_in: Some(Duration::from_secs(3).as_nanos() as u64), // 3 seconds
        session_expires_in: Some(Duration::from_secs(60 * 60 * 24 * 7).as_nanos() as u64), // 1 week
    };

    let arg = encode_one(settings).unwrap();

    let sender = None;

    ic.install_canister(canister_id, wasm_module, arg.clone(), sender);

    // Fast forward in time to allow the ic_siwe_provider_canister to be fully installed.
    for _ in 0..5 {
        ic.tick();
    }

    (ic, canister_id)
}

fn update<T: CandidType + for<'de> Deserialize<'de>>(
    ic: &PocketIc,
    sender: Principal,
    canister: Principal,
    method: &str,
    args: Vec<u8>,
) -> Result<T, String> {
    match ic.update_call(canister, sender, method, args) {
        Ok(WasmResult::Reply(data)) => decode_one(&data).unwrap(),
        Ok(WasmResult::Reject(error_message)) => Err(error_message.to_string()),
        Err(user_error) => Err(user_error.to_string()),
    }
}

fn query<T: CandidType + for<'de> Deserialize<'de>>(
    ic: &PocketIc,
    sender: Principal,
    canister: Principal,
    method: &str,
    args: Vec<u8>,
) -> Result<T, String> {
    match ic.query_call(canister, sender, method, args) {
        Ok(WasmResult::Reply(data)) => decode_one(&data).unwrap(),
        Ok(WasmResult::Reject(error_message)) => Err(error_message.to_string()),
        Err(user_error) => Err(user_error.to_string()),
    }
}

fn create_wallet() -> (ethers::signers::LocalWallet, String) {
    let wallet = LocalWallet::new(&mut rand::thread_rng());
    let h160 = wallet.address();
    let address = to_checksum(&h160, None);
    (wallet, address)
}

fn prepare_login_and_sign_message(
    ic: &PocketIc,
    ic_siwe_provider_canister: Principal,
    wallet: Wallet<SigningKey>,
    address: &str,
) -> (String, String) {
    let args = encode_one(address).unwrap();
    let siwe_message: String = update(
        ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "prepare_login",
        args,
    )
    .unwrap();
    let hash = hash_message(siwe_message.as_bytes());
    let signature = wallet.sign_hash(hash).unwrap().to_string();
    (format!("0x{}", signature.as_str()), siwe_message)
}

fn create_session_identity() -> BasicIdentity {
    let mut ed25519_seed = [0u8; 32];
    rand::thread_rng().fill(&mut ed25519_seed);
    let ed25519_keypair =
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&ed25519_seed).unwrap();
    BasicIdentity::from_key_pair(ed25519_keypair)
}

fn create_delegated_identity(
    identity: BasicIdentity,
    login_response: &LoginOkResponse,
    signature: Vec<u8>,
) -> DelegatedIdentity {
    // Create a delegated identity
    let signed_delegation = SignedDelegation {
        delegation: Delegation {
            pubkey: identity.public_key().unwrap(),
            expiration: login_response.expiration,
            targets: None,
            senders: None,
        },
        signature,
    };
    DelegatedIdentity::new(
        login_response.user_canister_pubkey.to_vec(),
        Box::new(identity),
        vec![signed_delegation],
    )
}

fn full_login(ic: &PocketIc, ic_siwe_provider_canister: Principal) -> (String, DelegatedIdentity) {
    let (wallet, address) = create_wallet();
    let (signature, _) =
        prepare_login_and_sign_message(ic, ic_siwe_provider_canister, wallet, &address);

    // Create a session identity
    let session_identity = create_session_identity();
    let session_pubkey = session_identity.public_key().unwrap();

    // Login
    let login_args = encode_args((signature, address.clone(), session_pubkey.clone())).unwrap();
    let login_response: LoginOkResponse = update(
        ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        login_args,
    )
    .unwrap();

    // Get the delegation
    let get_delegation_args = encode_args((
        address.clone(),
        session_pubkey.clone(),
        login_response.expiration,
    ))
    .unwrap();
    let get_delegation_response: SignedDelegationCandidType = query(
        ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_delegation",
        get_delegation_args,
    )
    .unwrap();

    // Create a delegated identity
    let delegated_identity = create_delegated_identity(
        session_identity,
        &login_response,
        get_delegation_response.signature.as_ref().to_vec(),
    );

    (address, delegated_identity)
}

#[test]
fn test_prepare_login_invalid_address() {
    let (ic, ic_siwe_provider_canister) = init();
    let address = encode_one("invalid address").unwrap();
    let response: Result<String, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "prepare_login",
        address,
    );
    assert_eq!(
        response.unwrap_err(),
        "Invalid Ethereum address: Must start with '0x' and be 42 characters long"
    );
}

#[test]
fn test_prepare_login_none_eip55_address() {
    let (ic, ic_siwe_provider_canister) = init();
    let address = encode_one("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
    let response: Result<String, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "prepare_login",
        address,
    );
    assert_eq!(
        response.unwrap_err(),
        "Invalid Ethereum address: Not EIP-55 encoded"
    );
}

#[test]
fn test_prepare_login_ok() {
    let (ic, ic_siwe_provider_canister) = init();
    let address = encode_one(VALID_ADDRESS).unwrap();
    let response: Result<String, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "prepare_login",
        address,
    );
    assert!(response.is_ok());
    let siwe_message: Message = response.unwrap().parse().unwrap();
    assert_eq!(
        siwe_message.address,
        hex::decode(&VALID_ADDRESS[2..]).unwrap().as_slice()
    );
}

#[test]
fn test_login_signature_too_short() {
    let (ic, ic_siwe_provider_canister) = init();
    let signature = "0xTOO-SHORT";
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY)).unwrap();
    let response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args,
    );
    assert_eq!(
        response.unwrap_err(),
        "Invalid signature: Must start with '0x' and be 132 characters long"
    );
}

#[test]
fn test_login_signature_too_long() {
    let (ic, ic_siwe_provider_canister) = init();
    let signature = "0xÖÖ809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809800000-TOO-LONG";
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY)).unwrap();
    let response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args,
    );
    assert_eq!(
        response.unwrap_err(),
        "Invalid signature: Must start with '0x' and be 132 characters long"
    );
}

#[test]
fn test_incorrect_signature_format() {
    let (ic, ic_siwe_provider_canister) = init();
    let signature = "0xÖÖ809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809809800000";
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY)).unwrap();
    let response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args,
    );
    assert_eq!(
        response.unwrap_err(),
        "Invalid signature: Hex decoding failed"
    );
}

#[test]
fn test_sign_in_message_expired() {
    let (ic, ic_siwe_provider_canister) = init();
    let (wallet, address) = create_wallet();
    let (signature, _) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);

    ic.advance_time(Duration::from_secs(10));

    let args = encode_args((signature, address, SESSION_KEY)).unwrap();
    let response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args,
    );
    assert_eq!(
        response.unwrap_err(),
        "Message not found for the given address"
    );
}

// A valid signature but with a different address
#[test]
fn test_sign_in_address_mismatch() {
    let (ic, ic_siwe_provider_canister) = init();
    let (wallet, address) = create_wallet();
    let (signature, _) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let args = encode_args((signature, VALID_ADDRESS, SESSION_KEY)).unwrap(); // Wrong address
    let response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args,
    );
    assert_eq!(
        response.unwrap_err(),
        "Message not found for the given address"
    );
}

// A manilulated signature with the correct address
#[test]
fn test_sign_in_signature_manipulated() {
    let (ic, ic_siwe_provider_canister) = init();
    let (wallet, address) = create_wallet();
    let (signature, _) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let manipulated_signature = format!("{}0000000000", &signature[..signature.len() - 10]);
    let args = encode_args((manipulated_signature, address, SESSION_KEY)).unwrap();
    let response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args,
    );
    assert_eq!(response.unwrap_err(), "Signature verification failed");
}

#[test]
fn test_sign_in_ok() {
    let (ic, ic_siwe_provider_canister) = init();
    let (wallet, address) = create_wallet();
    let (signature, _) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let args = encode_args((signature, address, SESSION_KEY)).unwrap();
    let response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args,
    );
    assert!(response.is_ok());
    assert!(response.unwrap().user_canister_pubkey.len() == 62);
}

#[test]
fn test_sign_in_replay_attack() {
    let (ic, ic_siwe_provider_canister) = init();
    let (wallet, address) = create_wallet();
    let (signature, _) =
        prepare_login_and_sign_message(&ic, ic_siwe_provider_canister, wallet, &address);
    let args = encode_args((signature, address, SESSION_KEY)).unwrap();
    let response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args.clone(),
    );
    assert!(response.is_ok());

    // Use the same signature again
    let second_response: Result<LoginOkResponse, String> = update(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "login",
        args,
    );
    assert_eq!(
        second_response.unwrap_err(),
        "Message not found for the given address"
    );
}

#[test]
fn test_sign_in_get_delegation_ok() {
    let (ic, ic_siwe_provider_canister) = init();
    let (address, delegated_identity) = full_login(&ic, ic_siwe_provider_canister);

    // Use the delegated identity to call the ic_siwe_provider_canister. Caller address should be the same as the
    // address generated by `create_wallet`.
    let caller_address_response: Result<String, String> = query(
        &ic,
        delegated_identity.sender().unwrap(),
        ic_siwe_provider_canister,
        "get_caller_address",
        encode_one(()).unwrap(),
    );

    assert!(caller_address_response.is_ok());
    assert_eq!(caller_address_response.unwrap(), address);

    // Make an anonymous call to the ic_siwe_provider_canister to get the address of the delegate identity. This should
    // be the same as the address generated by `create_wallet`.
    let get_address_response: Result<String, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_address",
        encode_one(delegated_identity.sender().unwrap().as_slice()).unwrap(),
    );

    assert!(get_address_response.is_ok());
    assert_eq!(get_address_response.unwrap(), address);

    // Make an anonymous call to the ic_siwe_provider_canister to get the principal of the delegate identity. This should
    // be the same as the principal represented by the delegate identity.
    let get_principal_response: Result<ByteBuf, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_principal",
        encode_one(address).unwrap(),
    );

    assert!(get_principal_response.is_ok());
    assert_eq!(
        get_principal_response.unwrap(),
        delegated_identity.sender().unwrap().as_slice()
    );
}

#[test]
fn test_sign_in_get_adress_unknown_principal() {
    let (ic, ic_siwe_provider_canister) = init();
    let (_, _) = full_login(&ic, ic_siwe_provider_canister);

    // Make an anonymous call to the ic_siwe_provider_canister to get the address of the delegate identity. This should
    // be the same as the address generated by `create_wallet`.
    let get_address_response: Result<String, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_address",
        encode_one("invalid principal".as_bytes()).unwrap(),
    );
    assert!(get_address_response.is_err());
    assert_eq!(
        get_address_response.unwrap_err(),
        "No address found for the given principal"
    );
}

#[test]
fn test_sign_in_get_principal_unknown_address() {
    let (ic, ic_siwe_provider_canister) = init();
    let (_, _) = full_login(&ic, ic_siwe_provider_canister);

    // Make an anonymous call to the ic_siwe_provider_canister to get the address of the delegate identity. This should
    // be the same as the address generated by `create_wallet`.
    let get_principal_response: Result<String, String> = query(
        &ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "get_principal",
        encode_one(VALID_ADDRESS).unwrap(),
    );
    assert!(get_principal_response.is_err());
    assert_eq!(
        get_principal_response.unwrap_err(),
        "No principal found for the given address"
    );
}

#[test]
fn test_sign_in_and_call_other_canister_ok() {
    let (ic, ic_siwe_provider_canister) = init();
    let (_, delegated_identity) = full_login(&ic, ic_siwe_provider_canister);

    let test_canister = ic.create_canister();
    ic.add_cycles(test_canister, 2_000_000_000_000);

    let test_canister_wasm_path: std::ffi::OsString =
        std::env::var_os("TEST_CANISTER_PATH").expect("Missing test_canister wasm file");
    let test_canister_wasm_module = std::fs::read(test_canister_wasm_path).unwrap();

    let sender = None;

    ic.install_canister(test_canister, test_canister_wasm_module, vec![], sender);

    let whoami_response: Result<String, String> = query(
        &ic,
        delegated_identity.sender().unwrap(),
        test_canister,
        "whoami",
        encode_one(()).unwrap(),
    );

    assert_eq!(
        whoami_response.unwrap(),
        delegated_identity.sender().unwrap().to_text()
    );
}
