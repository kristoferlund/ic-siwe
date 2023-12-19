mod get_delegation;
mod init;
mod login;
mod prepare_login;
mod types;
pub mod utils;

pub use get_delegation::get_delegation;
pub use init::init;
pub use login::login;
pub use prepare_login::prepare_login;
pub use types::delegation::SignedDelegation;
pub use types::settings::SettingsBuilder;

use crate::types::{settings::Settings, state::State};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);
    static SETTINGS: RefCell<Option<Settings>> = RefCell::new(None);
    static STATE: State = State::default();
}
