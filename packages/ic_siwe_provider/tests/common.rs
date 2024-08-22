#![allow(dead_code)]

use candid::{decode_one, encode_args, encode_one, CandidType, Principal};
use ethers::{
    core::k256::ecdsa::SigningKey,
    signers::{LocalWallet, Signer, Wallet},
    utils::{hash_message, to_checksum},
};
use ic_agent::{
    identity::{
        BasicIdentity, DelegatedIdentity, Delegation as AgentDelegation,
        SignedDelegation as AgentSignedDelegation,
    },
    Identity,
};
use ic_siwe::{delegation::SignedDelegation, login::LoginDetails};
use pocket_ic::{PocketIc, WasmResult};
use rand::Rng;
use serde::Deserialize;
use std::time::Duration;

#[derive(CandidType, Debug, Clone, PartialEq, Deserialize)]
pub enum RuntimeFeature {
    // Enabling this feature will include the app frontend URI as part of the identity seed.
    IncludeUriInSeed,
    // Disabling this feature will disable the mapping and permanent storage of the Ethereum address to the principal.
    DisableEthToPrincipalMapping,
    // Disabling this feature will disable the mapping and permanent storage of the principal to the Ethereum address.
    DisablePrincipalToEthMapping,
}

#[derive(CandidType)]
pub struct SettingsInput {
    pub domain: String,
    pub uri: String,
    pub salt: String,
    pub chain_id: Option<u32>,
    pub scheme: Option<String>,
    pub statement: Option<String>,
    pub sign_in_expires_in: Option<u64>,
    pub session_expires_in: Option<u64>,
    pub targets: Option<Vec<Principal>>,
    pub runtime_features: Option<Vec<RuntimeFeature>>,
}

pub const VALID_ADDRESS: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
pub const SESSION_KEY: &[u8] = &[
    48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 220, 227, 2, 129, 72, 36, 43, 220, 96, 102, 225,
    92, 98, 163, 114, 182, 117, 181, 51, 15, 219, 197, 104, 55, 123, 245, 74, 181, 35, 181, 171,
    196,
]; // DER encoded session key
pub const NONCE: &str = "nonce123";

pub fn valid_settings(canister_id: Principal, targets: Option<Vec<Principal>>) -> SettingsInput {
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
        runtime_features: Some(vec![RuntimeFeature::IncludeUriInSeed]),
    }
}

pub fn create_canister(ic: &PocketIc) -> (Principal, Vec<u8>) {
    let canister_id = ic.create_canister();
    ic.add_cycles(canister_id, 2_000_000_000_000);

    let wasm_path: std::ffi::OsString =
        std::env::var_os("IC_SIWE_PROVIDER_PATH").expect("Missing ic_siwe_provider wasm file");
    let wasm_module = std::fs::read(wasm_path).unwrap();

    (canister_id, wasm_module)
}

pub fn init(ic: &PocketIc, targets: Option<Vec<Principal>>) -> (Principal, Option<Vec<Principal>>) {
    let (canister_id, wasm_module) = create_canister(ic);
    let settings = valid_settings(canister_id, targets.clone());
    let arg = encode_one(settings).unwrap();
    let sender = None;

    ic.install_canister(canister_id, wasm_module, arg.clone(), sender);

    // Fast forward in time to allow the ic_siwe_provider_canister to be fully installed.
    for _ in 0..5 {
        ic.tick();
    }

    (canister_id, targets)
}

pub fn update<T: CandidType + for<'de> Deserialize<'de>>(
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

pub fn query<T: CandidType + for<'de> Deserialize<'de>>(
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

pub fn create_wallet() -> (ethers::signers::LocalWallet, String) {
    let wallet = LocalWallet::new(&mut rand::thread_rng());
    let h160 = wallet.address();
    let address = to_checksum(&h160, None);
    (wallet, address)
}

#[derive(CandidType, Deserialize)]
pub struct PrepareLoginOkResponse {
    pub siwe_message: String,
    pub nonce: String,
}

pub fn prepare_login_and_sign_message(
    ic: &PocketIc,
    ic_siwe_provider_canister: Principal,
    wallet: Wallet<SigningKey>,
    address: &str,
) -> (String, PrepareLoginOkResponse) {
    let args = encode_one(address).unwrap();
    let prepare_login_ok_response: PrepareLoginOkResponse = update(
        ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_prepare_login",
        args,
    )
    .unwrap();
    let hash = hash_message(prepare_login_ok_response.siwe_message.as_bytes());
    let signature = wallet.sign_hash(hash).unwrap().to_string();
    (
        format!("0x{}", signature.as_str()),
        prepare_login_ok_response,
    )
}

pub fn create_session_identity() -> BasicIdentity {
    let mut ed25519_seed = [0u8; 32];
    rand::thread_rng().fill(&mut ed25519_seed);
    let ed25519_keypair =
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&ed25519_seed).unwrap();
    BasicIdentity::from_key_pair(ed25519_keypair)
}

pub fn create_delegated_identity(
    identity: BasicIdentity,
    login_response: &LoginDetails,
    signature: Vec<u8>,
    targets: Option<Vec<Principal>>,
) -> DelegatedIdentity {
    // Create a delegated identity
    let signed_delegation = AgentSignedDelegation {
        delegation: AgentDelegation {
            pubkey: identity.public_key().unwrap(),
            expiration: login_response.expiration,
            targets,
        },
        signature,
    };
    DelegatedIdentity::new(
        login_response.user_canister_pubkey.to_vec(),
        Box::new(identity),
        vec![signed_delegation],
    )
}

pub fn full_login(
    ic: &PocketIc,
    ic_siwe_provider_canister: Principal,
    targets: Option<Vec<Principal>>,
) -> (String, DelegatedIdentity) {
    let (wallet, address) = create_wallet();
    let (signature, prepare_login_ok_response) =
        prepare_login_and_sign_message(ic, ic_siwe_provider_canister, wallet, &address);

    // Create a session identity
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
    let login_response: LoginDetails = update(
        ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_login",
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
    let get_delegation_response: SignedDelegation = query(
        ic,
        Principal::anonymous(),
        ic_siwe_provider_canister,
        "siwe_get_delegation",
        get_delegation_args,
    )
    .unwrap();

    // Create a delegated identity
    let delegated_identity = create_delegated_identity(
        session_identity,
        &login_response,
        get_delegation_response.signature.as_ref().to_vec(),
        targets,
    );

    (address, delegated_identity)
}
