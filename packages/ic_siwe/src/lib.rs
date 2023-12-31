/*!

This library allow Internet Computer canisters to implement the Sign In with Ethereum (SIWE) standard for
Ethereum login [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361). Delegate identities are created based
on signed SIWE messages generated by the library.

# Crate features

The library has one optional feature that is disabled by default.

* `nonce` - Enables the generation of nonces for SIWE messages. This feature initializes a random number
generator with a seed from the management canister. The random number generator then is used to generate
unique nonces for each generated SIWE message. Nonces don't add any additional security to the SIWE login
flow but are required by the SIWE standard. When this feature is disabled, the nonce is always set to the
hex encoded string `Not in use`.

*/
pub mod delegation;
pub mod eth;
pub(crate) mod hash;
pub(crate) mod init;
pub mod login;
pub(crate) mod rand;
pub mod settings;
pub mod signature_map;
pub mod siwe;
pub(crate) mod time;

pub use init::init;

use settings::Settings;
use siwe::SiweMessage;
use std::{cell::RefCell, collections::HashMap};

#[cfg(feature = "nonce")]
use rand_chacha::ChaCha20Rng;

thread_local! {
    // The random number generator is used to generate nonces for SIWE messages. This feature is
    // optional and can be enabled by setting the `nonce` feature flag.
    #[cfg(feature = "nonce")]
    static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);

    // The settings control the behavior of the SIWE library. The settings must be initialized
    // before any other library functions are called.
    static SETTINGS: RefCell<Option<Settings>> = RefCell::new(None);

    // SIWE messages are stored in global state during the login process. The key is the
    // Ethereum address as a byte array and the value is the SIWE message. After a successful
    // login, the SIWE message is removed from the state.
    static SIWE_MESSAGES: RefCell<HashMap<Vec<u8>, SiweMessage>> = RefCell::new(HashMap::new());
}
