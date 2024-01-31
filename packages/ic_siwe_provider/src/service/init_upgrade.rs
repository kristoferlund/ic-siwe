use candid::{CandidType, Principal};
use ic_cdk::{init, post_upgrade};
use ic_siwe::settings::SettingsBuilder;
use serde::Deserialize;

/// Represents the settings that determine the behavior of the SIWE library. It includes settings such as domain, scheme, statement,
/// and expiration times for sessions and sign-ins.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SettingsInput {
    /// The domain from where the frontend that uses SIWE is served.
    pub domain: String,

    /// The full URI, potentially including port number of the frontend that uses SIWE.
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
}

/// Initialize the SIWE library with the given settings.
///
/// Required fields are `domain`, `uri`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `uri` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
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
