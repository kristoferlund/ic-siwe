use crate::{settings::Settings, SETTINGS};

/// Initializes the SIWE library with the provided settings. Must be called before any other SIWE functions. Use the [SettingsBuilder](crate::settings::SettingsBuilder)  to create a [Settings] object.
///
/// # Parameters
///
/// * `settings` - The SIWE settings to be initialized.
///
/// # Examples
///
/// ```
/// use ic_siwe::{init, settings::SettingsBuilder};
///
/// let settings = SettingsBuilder::new("example.com", "http://example.com", "salt")
///   .scheme("https")
///   .statement("Sign in with Ethereum")
///   .chain_id(1)
///   .sign_in_expires_in(300_000_000_000) // 5 minutes in nanoseconds
///   .build()
///   .unwrap();
///
/// init(settings).unwrap();
/// ```
///
pub fn init(settings: Settings) -> Result<(), String> {
    SETTINGS.set(Some(settings));

    init_rng();

    Ok(())
}

fn init_rng() {
    use crate::RNG;
    use candid::Principal;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use std::time::Duration;

    // Initialize the random number generator with a seed from the management canister.
    ic_cdk_timers::set_timer(Duration::ZERO, || {
        ic_cdk::spawn(async {
            let (seed,): ([u8; 32],) =
                ic_cdk::call(Principal::management_canister(), "raw_rand", ())
                    .await
                    .unwrap();
            RNG.with_borrow_mut(|rng| *rng = Some(ChaCha20Rng::from_seed(seed)));
        })
    });
}
