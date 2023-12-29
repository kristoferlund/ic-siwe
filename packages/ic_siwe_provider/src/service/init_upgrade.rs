use candid::{CandidType, Principal};
use ic_cdk::{init, post_upgrade};
use ic_siwe::settings::SettingsBuilder;
use serde::Deserialize;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SettingsInput {
    pub domain: String,
    pub uri: String,
    pub salt: String,
    pub chain_id: Option<u32>,
    pub scheme: Option<String>,
    pub statement: Option<String>,
    pub sign_in_expires_in: Option<u64>,
    pub session_expires_in: Option<u64>,
    pub targets: Option<Vec<String>>,
}

fn siwe_init(settings: SettingsInput) {
    let mut builder = SettingsBuilder::new(&settings.domain, &settings.uri, &settings.salt);

    // Optional fields
    if let Some(chain_id) = settings.chain_id {
        builder = builder.chain_id(chain_id);
    }
    if let Some(scheme) = settings.scheme {
        builder = builder.scheme(scheme);
    }
    if let Some(statement) = settings.statement {
        builder = builder.statement(statement);
    }
    if let Some(expire_in) = settings.sign_in_expires_in {
        builder = builder.sign_in_expires_in(expire_in);
    }
    if let Some(session_expire_in) = settings.session_expires_in {
        builder = builder.session_expires_in(session_expire_in);
    }
    if let Some(targets) = settings.targets {
        let targets: Vec<Principal> = targets
            .into_iter()
            .map(|t| Principal::from_text(t).unwrap())
            .collect();
        // Make sure the canister id of this canister is in the list of targets
        let canister_id = ic_cdk::id();
        if !targets.contains(&canister_id) {
            panic!(
                "ic_siwe_provider canister id {} not in the list of targets",
                canister_id
            );
        }
        builder = builder.targets(targets);
    }

    // Build and initialize SIWE
    ic_siwe::init(builder.build().unwrap()).unwrap();
}

// The siwe_init function is called when the canister is created to initialize the SIWE library.
#[init]
fn init(settings: SettingsInput) {
    siwe_init(settings);
}

// Make sure to call the init function after upgrading the canister.
#[post_upgrade]
fn upgrade(settings: SettingsInput) {
    siwe_init(settings);
}
