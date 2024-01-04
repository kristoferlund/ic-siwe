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

use rand_chacha::ChaCha20Rng;
use settings::Settings;
use siwe::SiweMessage;
use std::{cell::RefCell, collections::HashMap};

thread_local! {
    // The random number generator is used to generate nonces for SIWE messages. This feature is
    // optional and can be enabled by setting the `nonce` feature flag.
    static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);

    // The settings control the behavior of the SIWE library. The settings must be initialized
    // before any other library functions are called.
    static SETTINGS: RefCell<Option<Settings>> = RefCell::new(None);

    // SIWE messages are stored in global state during the login process. The key is the
    // Ethereum address as a byte array and the value is the SIWE message. After a successful
    // login, the SIWE message is removed from the state.
    static SIWE_MESSAGES: RefCell<HashMap<Vec<u8>, SiweMessage>> = RefCell::new(HashMap::new());
}
