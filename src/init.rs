use candid::Principal;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::time::Duration;

use crate::{types::settings::Settings, RNG, SETTINGS};

/// Initializes the SIWE library with the provided settings. Must be called before any other SIWE functions.
///
/// # Parameters
///
/// * `settings` - The SIWE settings to be initialized.
///
/// # Returns
///
/// `Result<(), String>` - Ok on success, or an error message on failure.
pub fn init(settings: Settings) -> Result<(), String> {
    SETTINGS.set(Some(settings));

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

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::types::settings::SettingsBuilder;

    #[test]
    fn test_valid_settings() {
        let builder = SettingsBuilder::new("example.com", "http://example.com")
            .scheme("https")
            .statement("Sign in with Ethereum")
            .chain_id(1)
            .sign_in_expires_in(300_000_000_000); // 5 minutes in nanoseconds

        assert!(builder.build().is_ok());
    }

    #[test]
    fn test_invalid_domain() {
        let builder = SettingsBuilder::new("invalid domain", "http://example.com");
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_invalid_scheme() {
        let builder = SettingsBuilder::new("example.com", "http://example.com").scheme("ftp"); // Invalid scheme

        assert!(builder.build().is_err());
    }

    #[test]
    fn test_invalid_statement() {
        let builder = SettingsBuilder::new("example.com", "http://example.com")
            .statement("Invalid\nStatement"); // Invalid because of newline

        assert!(builder.build().is_err());
    }

    #[test]
    fn test_invalid_uri() {
        let builder = SettingsBuilder::new("example.com", "invalid_uri");
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_invalid_sign_in_expires_in_zero() {
        let builder =
            SettingsBuilder::new("example.com", "http://example.com").sign_in_expires_in(0); // Invalid because it's zero

        assert!(builder.build().is_err());
    }

    #[test]
    fn test_omitted_domain() {
        let builder = SettingsBuilder::new("", "http://example.com");
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_omitted_uri() {
        let builder = SettingsBuilder::new("example.com", "");
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_omitted_scheme() {
        let builder = SettingsBuilder::new("example.com", "http://example.com").scheme("");
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_omitted_statement() {
        let builder = SettingsBuilder::new("example.com", "http://example.com").statement("");
        assert!(builder.build().is_ok()); // Assuming empty statement is valid
    }
}
