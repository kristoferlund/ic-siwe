use candid::Principal;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::time::Duration;

use crate::{types::settings::Settings, RNG, SETTINGS};

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
pub fn init(settings: Settings) -> Result<(), String> {
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
