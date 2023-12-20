pub mod delegation;
pub mod eth;
pub mod hash;
pub mod init;
pub mod login;
pub mod rand;
pub mod settings;
pub mod signature_map;
pub mod siwe;
pub mod time;

pub use init::init;

use ic_certified_map::{Hash, RbTree};
use rand_chacha::ChaCha20Rng;
use settings::Settings;
use signature_map::SignatureMap;
use siwe::SiweMessage;
use std::{cell::RefCell, collections::HashMap};

pub(crate) type AssetHashes = RbTree<&'static str, Hash>;

pub(crate) struct State {
    pub sigs: RefCell<SignatureMap>,
    pub asset_hashes: RefCell<AssetHashes>,
    pub siwe_messages: RefCell<HashMap<Vec<u8>, SiweMessage>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            sigs: RefCell::new(SignatureMap::default()),
            asset_hashes: RefCell::new(AssetHashes::default()),
            siwe_messages: RefCell::new(HashMap::new()),
        }
    }
}

thread_local! {
    static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);
    static SETTINGS: RefCell<Option<Settings>> = RefCell::new(None);
    static STATE: State = State::default();
}
