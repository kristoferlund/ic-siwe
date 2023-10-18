use candid::Principal;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::time::Duration;
use url::Url;

use crate::{siwe_settings::SiweSettings, RNG, SETTINGS};

fn validate_scheme(scheme: &str) -> Result<String, String> {
    if scheme == "http" || scheme == "https" {
        return Ok(scheme.to_string());
    }
    Err(String::from("Invalid scheme"))
}

fn validate_domain(scheme: &str, domain: &str) -> Result<String, String> {
    let url_str = format!("{}://{}", scheme, domain);
    let parsed_url = Url::parse(&url_str).map_err(|_| String::from("Invalid domain"))?;
    if !parsed_url.has_authority() {
        Err(String::from("Invalid domain"))
    } else {
        Ok(parsed_url.host_str().unwrap().to_string())
    }
}

fn validate_statement(statement: &str) -> Result<String, String> {
    if statement.contains("\n") {
        return Err(String::from("Invalid statement"));
    }
    Ok(statement.to_string())
}

fn validate_uri(uri: &str) -> Result<String, String> {
    let parsed_uri = Url::parse(uri).map_err(|_| String::from("Invalid URI"))?;
    if !parsed_uri.has_host() {
        Err(String::from("Invalid URI"))
    } else {
        Ok(uri.to_string())
    }
}

/// Initializes the SIWE settings.
///
/// This function validates and sets the SIWE settings based on the given `SiweSettings` struct.
/// The settings include scheme, domain, statement, URI, and chain ID.
///
/// # Parameters
///
/// * `settings: SiweSettings<'_>` - A struct containing the SIWE settings.
///
///     - `scheme: Option<&str>`: The URI scheme of the origin of the request.
///       Allowed values are "http" and "https". Default is "https" if not provided.
///
///     - `domain: &str`: The domain that is requesting the signing.
///       Must be a valid RFC 3986 authority.
///
///     - `statement: Option<&str>`: A human-readable ASCII assertion that the user will sign.
///       Must not include '\n' (the byte 0x0a).
///
///     - `uri: &str`: An RFC 3986 URI referring to the resource that is the subject of the signing.
///
///     - `chain_id: u32`: The EIP-155 Chain ID tzo which the session is bound.
///       Must be greater than 0.
///
/// # Returns
///
/// Returns a `Result<(), String>` indicating the success or failure of the initialization.
/// Each setting is validated according to the rules specified in EIP-4361.
///
/// # Errors
///
/// Returns an `Err(String)` if any of the settings are invalid.
pub fn init(settings: SiweSettings) -> Result<(), String> {
    validate_domain(&settings.scheme, &settings.domain)?;
    validate_scheme(&settings.scheme)?;
    validate_statement(&settings.statement)?;
    validate_uri(&settings.uri)?;

    SETTINGS
        .set(settings)
        .map_err(|_| String::from("Settings are already set"))?;

    ic_cdk_timers::set_timer(Duration::ZERO, || {
        ic_cdk::spawn(async {
            let (seed,): ([u8; 32],) =
                ic_cdk::call(Principal::management_canister(), "raw_rand", ())
                    .await
                    .unwrap();
            RNG.with(|rng| *rng.borrow_mut() = Some(ChaCha20Rng::from_seed(seed)));
        })
    });

    Ok(())
}
