pub mod delegation;
pub mod eth;
pub mod get_delegation;
pub mod hash;
pub mod init;
pub mod login;
pub mod prepare_login;
pub mod rand;
pub mod settings;
pub mod signature_map;
pub mod siwe;
pub mod state;
pub mod time;

pub use get_delegation::get_delegation;
pub use init::init;
pub use login::login;
pub use prepare_login::prepare_login;

use rand_chacha::ChaCha20Rng;
use settings::Settings;
use state::State;
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);
    static SETTINGS: RefCell<Option<Settings>> = RefCell::new(None);
    static STATE: State = State::default();
}
