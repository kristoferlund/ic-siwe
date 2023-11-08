use candid::Principal;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::time::Duration;
use url::Url;

use crate::{siwe_settings::SiweSettings, RNG, SETTINGS};

// Validates the provided URI scheme.
///
/// # Parameters
///
/// * `scheme: &str` - The URI scheme to validate.
///
/// # Returns
///
/// Returns a `Result<String, String>` containing the valid scheme or an error message.
fn validate_scheme(scheme: &str) -> Result<String, String> {
    if scheme == "http" || scheme == "https" {
        return Ok(scheme.to_string());
    }
    Err(String::from("Invalid scheme"))
}

/// Validates the provided domain based on the given scheme.
///
/// # Parameters
///
/// * `scheme: &str` - The URI scheme associated with the domain.
/// * `domain: &str` - The domain to validate.
///
/// # Returns
///
/// Returns a `Result<String, String>` containing the valid domain or an error message.
fn validate_domain(scheme: &str, domain: &str) -> Result<String, String> {
    let url_str = format!("{}://{}", scheme, domain);
    let parsed_url = Url::parse(&url_str).map_err(|_| String::from("Invalid domain"))?;
    if !parsed_url.has_authority() {
        Err(String::from("Invalid domain"))
    } else {
        Ok(parsed_url.host_str().unwrap().to_string())
    }
}

/// Validates the provided statement.
///
/// # Parameters
///
/// * `statement: &str` - The statement to validate.
///
/// # Returns
///
/// Returns a `Result<String, String>` containing the valid statement or an error message.
fn validate_statement(statement: &str) -> Result<String, String> {
    if statement.contains("\n") {
        return Err(String::from("Invalid statement"));
    }
    Ok(statement.to_string())
}

/// Validates the provided URI.
///
/// # Parameters
///
/// * `uri: &str` - The URI to validate.
///
/// # Returns
///
/// Returns a `Result<String, String>` containing the valid URI or an error message.
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
/// This function validates and sets the SIWE settings based on the provided `SiweSettings` struct.
/// The settings include scheme, domain, statement, URI, and chain ID.
///
/// # Parameters
///
/// * `settings: SiweSettings` - A struct containing the SIWE settings.
///
/// # Returns
///
/// Returns a `Result<(), String>` indicating the success or failure of the initialization.
/// Each setting is validated according to their respective rules.
///
/// # Errors
///
/// Returns an `Err(String)` if any of the settings are invalid.
pub fn init(settings: SiweSettings) -> Result<(), String> {
    validate_domain(&settings.scheme, &settings.domain)?;
    validate_scheme(&settings.scheme)?;
    validate_statement(&settings.statement)?;
    validate_uri(&settings.uri)?;

    SETTINGS.set(Some(settings));

    ic_cdk_timers::set_timer(Duration::ZERO, || {
        ic_cdk::spawn(async {
            let (seed,): ([u8; 32],) =
                ic_cdk::call(Principal::management_canister(), "raw_rand", ())
                    .await
                    .unwrap();
            RNG.with_borrow_mut(|rng| *rng = Some(ChaCha20Rng::from_seed(seed)));
        })
    });

    Ok(())
}
