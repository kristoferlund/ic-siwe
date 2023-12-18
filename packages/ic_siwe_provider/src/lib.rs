#![allow(dead_code)]

use candid::{CandidType, Principal};
use ic_cdk::{init, post_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Blob;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::cell::RefCell;

type Memory = VirtualMemory<DefaultMemoryImpl>;

type PublicKey = ByteBuf;
type CanisterPublicKey = PublicKey;

extern crate ic_siwe;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static PRINCIPAL_ADDRESS: RefCell<StableBTreeMap<Blob<29>, [u8;32], Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static ADDRESS_PRINCIPAL: RefCell<StableBTreeMap<[u8;32], Blob<29>, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

}

#[query]
fn get_principal(address: String) -> Result<ByteBuf, String> {
    ADDRESS_PRINCIPAL.with(|ap| {
        ap.borrow()
            .get(&address.as_bytes().try_into().unwrap())
            .map_or(
                Err("No principal found for the given address".to_string()),
                |p| Ok(ByteBuf::from(p.as_ref().to_vec())),
            )
    })
}

#[query]
fn get_address(principal: ByteBuf) -> Result<ByteBuf, String> {
    let principal: Blob<29> = Principal::self_authenticating(principal).as_slice()[..29]
        .try_into()
        .unwrap();

    // Perform the lookup
    PRINCIPAL_ADDRESS.with(|pa| {
        pa.borrow().get(&principal).map_or(
            Err("No address found for the given principal".to_string()),
            |a| Ok(ByteBuf::from(a.to_vec())),
        )
    })
}

// Login the user by verifying the signature of the SIWE message. If the signature is valid, the
// public key is returned. In this step, the delegation is also prepared to be fetched in the next
// step.
#[update]
fn login(
    signature: String,
    address: String,
    session_key: PublicKey,
) -> Result<CanisterPublicKey, String> {
    match ic_siwe::login(&signature, &address, session_key) {
        Ok(pk) => {
            let principal: Blob<29> = Principal::self_authenticating(&pk).as_slice()[..29]
                .try_into()
                .unwrap();
            let address: [u8; 32] = address.as_bytes().try_into().unwrap();

            PRINCIPAL_ADDRESS.with_borrow_mut(|pa| {
                pa.insert(principal, address);
            });

            ADDRESS_PRINCIPAL.with_borrow_mut(|ap| {
                ap.insert(address, principal);
            });

            Ok(pk)
        }
        Err(e) => Err(e.to_string()),
    }
}

// Prepare the login by generating a challenge (the SIWE message) and returning it to the caller.
#[update]
fn prepare_login(address: String) -> Result<String, String> {
    ic_siwe::prepare_login(&address).map(|m| m.into())
}

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct Settings {
    pub domain: String,
    pub uri: String,
    pub salt: String,
    pub chain_id: Option<u32>,
    pub scheme: Option<String>,
    pub statement: Option<String>,
    pub sign_in_expires_in: Option<u64>,
    pub session_expires_in: Option<u64>,
}

fn siwe_init(settings: Settings) {
    let mut builder =
        ic_siwe::SettingsBuilder::new(&settings.domain, &settings.uri, &settings.salt);

    // Optional fields
    if let Some(chain_id) = settings.chain_id {
        builder = builder.chain_id(chain_id);
    }
    if let Some(scheme) = settings.scheme {
        builder = builder.scheme(&scheme);
    }
    if let Some(statement) = settings.statement {
        builder = builder.statement(&statement);
    }
    if let Some(expire_in) = settings.sign_in_expires_in {
        builder = builder.sign_in_expires_in(expire_in);
    }
    if let Some(session_expire_in) = settings.session_expires_in {
        builder = builder.session_expires_in(session_expire_in);
    }

    // Build and initialize SIWE
    ic_siwe::init(builder.build().unwrap()).unwrap();
}

// The siwe_init function is called when the canister is created to initialize the SIWE library.
#[init]
fn init(settings: Settings) {
    siwe_init(settings);
}

// Make sure to call the init function after upgrading the canister.
#[post_upgrade]
fn upgrade(settings: Settings) {
    siwe_init(settings);
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use candid::{decode_one, encode_one, CandidType, Principal};
    use pocket_ic::{PocketIc, WasmResult};
    use serde::Deserialize;
    use siwe::Message;

    use crate::Settings;

    const VALID_ADDRESS: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

    fn init() -> (PocketIc, Principal) {
        let ic = PocketIc::new();
        let canister_id = ic.create_canister();
        ic.add_cycles(canister_id, 2_000_000_000_000);

        let wasm_path: std::ffi::OsString =
            std::env::var_os("WASM_PATH").expect("Missing counter wasm file");
        let wasm_module = std::fs::read(wasm_path).unwrap();

        let settings = Settings {
            domain: "127.0.0.1".to_string(),
            uri: "http://127.0.0.1:5173".to_string(),
            salt: "dummy salt".to_string(),
            chain_id: Some(10),
            scheme: Some("http".to_string()),
            statement: Some("Login to the app".to_string()),
            sign_in_expires_in: Some(Duration::from_secs(60 * 5).as_nanos() as u64), // 5 minutes
            session_expires_in: Some(Duration::from_secs(60 * 60 * 24 * 7).as_nanos() as u64), // 1 week
        };

        let arg = encode_one(settings).unwrap();

        let sender = None;

        ic.install_canister(canister_id, wasm_module, arg.clone(), sender);

        // Fast forward in time to allow the canister to be fully installed.
        for _ in 0..5 {
            ic.tick();
        }

        (ic, canister_id)
    }

    fn update<T: CandidType + for<'de> Deserialize<'de>>(
        ic: &PocketIc,
        canister: Principal,
        method: &str,
        args: Vec<u8>,
    ) -> Result<T, String> {
        match ic.update_call(canister, Principal::anonymous(), method, args) {
            Ok(WasmResult::Reply(data)) => decode_one(&data).unwrap(),
            Ok(WasmResult::Reject(error_message)) => Err(error_message.to_string()),
            Err(user_error) => Err(user_error.to_string()),
        }
    }

    #[test]
    fn test_prepare_login_invalid_address() {
        let (ic, canister) = init();
        let address = encode_one("invalid address").unwrap();
        let response: Result<String, String> = update(&ic, canister, "prepare_login", address);
        assert_eq!(
            response.unwrap_err(),
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long"
        );
    }

    #[test]
    fn test_prepare_login_none_eip55_address() {
        let (ic, canister) = init();
        let address = encode_one("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let response: Result<String, String> = update(&ic, canister, "prepare_login", address);
        assert_eq!(
            response.unwrap_err(),
            "Invalid Ethereum address: Not EIP-55 encoded"
        );
    }

    #[test]
    fn test_prepare_login_ok() {
        let (ic, canister) = init();
        let address = encode_one(VALID_ADDRESS).unwrap();
        let response: Result<String, String> = update(&ic, canister, "prepare_login", address);
        assert!(response.is_ok());
        let siwe_message: Message = response.unwrap().parse().unwrap();
        assert_eq!(
            siwe_message.address,
            hex::decode(&VALID_ADDRESS[2..]).unwrap().as_slice()
        );
    }
}
