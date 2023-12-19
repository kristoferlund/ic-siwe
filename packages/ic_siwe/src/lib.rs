pub mod get_delegation;
pub mod init;
pub mod login;
pub mod prepare_login;
pub mod types;
pub mod utils;

pub use get_delegation::get_delegation;
pub use init::init;
pub use login::login;
pub use prepare_login::prepare_login;

use crate::types::{settings::Settings, state::State};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);
    static SETTINGS: RefCell<Option<Settings>> = RefCell::new(None);
    static STATE: State = State::default();
}
