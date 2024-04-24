use candid::{CandidType, Principal};
use ic_cdk::{init, post_upgrade};
use ic_siwe::settings::SettingsBuilder;
use serde::Deserialize;

use crate::SETTINGS;

#[derive(CandidType, Debug, Clone, PartialEq, Deserialize)]
pub enum RuntimeFeature {
    // Include the app frontend URI as part of the identity seed.
    IncludeUriInSeed,

    // Disable the mapping of Ethereum address to principal. This also disables canister endpoints `get_principal`.
    DisableEthToPrincipalMapping,

    // Disable the mapping of principal to Ethereum address. This also disables canister endpoints `get_address` and `get_caller_address`.
    DisablePrincipalToEthMapping,
}

/// Represents the settings that determine the behavior of the SIWE library. It includes settings such as domain, scheme, statement,
/// and expiration times for sessions and sign-ins.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SettingsInput {
    /// The full domain, including subdomains, from where the frontend that uses SIWE is served.
    /// Example: "example.com" or "sub.example.com".
    pub domain: String,

    /// The full URI, potentially including port number of the frontend that uses SIWE.
    /// Example: "https://example.com" or "https://sub.example.com:8080".
    pub uri: String,

    /// The salt is used when generating the seed that uniquely identifies each user principal. The salt can only contain
    /// printable ASCII characters.
    pub salt: String,

    /// The Ethereum chain ID for ic-siwe, defaults to 1 (Ethereum mainnet).
    pub chain_id: Option<u32>,

    // The scheme used to serve the frontend that uses SIWE. Defaults to "https".
    pub scheme: Option<String>,

    /// The statement is a message or declaration, often presented to the user by the Ethereum wallet
    pub statement: Option<String>,

    /// The TTL for a sign-in message in nanoseconds. After this time, the sign-in message will be pruned.
    pub sign_in_expires_in: Option<u64>,

    /// The TTL for a session in nanoseconds.
    pub session_expires_in: Option<u64>,

    /// The list of canisters for which the identity delegation is allowed. Defaults to None, which means
    /// that the delegation is allowed for all canisters. If specified, the canister id of this canister must be in the list.
    pub targets: Option<Vec<String>>,

    pub runtime_features: Option<Vec<RuntimeFeature>>,
}

/// Initialize the SIWE library with the given settings.
///
/// Required fields are `domain`, `uri`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `uri` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
fn siwe_init(settings_input: SettingsInput) {
    let mut ic_siwe_settings = SettingsBuilder::new(
        &settings_input.domain,
        &settings_input.uri,
        &settings_input.salt,
    );

    // Optional fields
    if let Some(chain_id) = settings_input.chain_id {
        ic_siwe_settings = ic_siwe_settings.chain_id(chain_id);
    }
    if let Some(scheme) = settings_input.scheme {
        ic_siwe_settings = ic_siwe_settings.scheme(scheme);
    }
    if let Some(statement) = settings_input.statement {
        ic_siwe_settings = ic_siwe_settings.statement(statement);
    }
    if let Some(expire_in) = settings_input.sign_in_expires_in {
        ic_siwe_settings = ic_siwe_settings.sign_in_expires_in(expire_in);
    }
    if let Some(session_expire_in) = settings_input.session_expires_in {
        ic_siwe_settings = ic_siwe_settings.session_expires_in(session_expire_in);
    }
    if let Some(targets) = settings_input.targets {
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
        ic_siwe_settings = ic_siwe_settings.targets(targets);
    }

    SETTINGS.with_borrow_mut(|provider_settings| {
        if let Some(runtime_features) = settings_input.runtime_features {
            for feature in runtime_features {
                match feature {
                    RuntimeFeature::IncludeUriInSeed => {
                        ic_siwe_settings = ic_siwe_settings.runtime_features(vec![
                            ic_siwe::settings::RuntimeFeature::IncludeUriInSeed,
                        ]);
                    }
                    RuntimeFeature::DisableEthToPrincipalMapping => {
                        provider_settings.disable_eth_to_principal_mapping = true;
                    }
                    RuntimeFeature::DisablePrincipalToEthMapping => {
                        provider_settings.disable_principal_to_eth_mapping = true;
                    }
                }
            }
        }

        // Build and initialize SIWE
        ic_siwe::init(ic_siwe_settings.build().unwrap()).unwrap();
    });
}

/// `init` is called when the canister is created. It initializes the SIWE library with the given settings.
///
/// Required fields are `domain`, `uri`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `uri` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
#[init]
fn init(settings: SettingsInput) {
    siwe_init(settings);
}

/// `post_upgrade` is called when the canister is upgraded. It initializes the SIWE library with the given settings.
///
/// Required fields are `domain`, `uri`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `uri` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
#[post_upgrade]
fn upgrade(settings: SettingsInput) {
    siwe_init(settings);
}
