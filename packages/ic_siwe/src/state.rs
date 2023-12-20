use std::{cell::RefCell, collections::HashMap};

use ic_certified_map::{Hash, RbTree};

use crate::siwe::SiweMessage;

use super::signature_map::SignatureMap;

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
