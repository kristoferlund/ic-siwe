/*!
Using the pre built `ic_siwe_provider` canister is the easiest way to integrate Ethereum wallet authentication
into your [Internet Computer](https://internetcomputer.org) application.

The canister is designed as a plug-and-play solution for developers, enabling easy integration into existing
IC applications with minimal coding requirements. By adding the pre built `ic_siwe_provider` canister to the
`dfx.json` of an IC project, developers can quickly enable Ethereum wallet-based authentication for their
applications. The canister simplifies the authentication flow by managing the creation and verification of SIWE
messages and handling user session management.

`ic_siwe_provider` is part of the [ic-siwe](https://github.com/kristoferlund/ic-siwe) project that enables
Ethereum wallet-based authentication for applications on the Internet Computer (IC) platform. The goal of the
project is to enhance the interoperability between Ethereum and the Internet Computer platform, enabling
developers to build applications that leverage the strengths of both platforms.

## Features

- **Prebuilt**: The canister is pre built and ready to use.
- **Configurable**: The `ic_siwe_provider` canister allows developers to customize the SIWE authentication
  flow to suit their needs.
- **Easy Integration**: The canister can be easily integrated into any Internet Computer application, independent
  of the application's programming language.
- **Keeps Ethereum Wallets Private**: The canister never has access to the user's Ethereum wallet, ensuring that
  the user's private keys are never exposed.
- **Session Identity Uniqueness**: Ensures that session identities are specific to each application's context,
  preventing cross-app identity misuse.
- **Consistent Principal Generation**: Guarantees that logging in with an Ethereum wallet consistently produces
  the same Principal, irrespective of the client used.
- **Direct Ethereum Address to Principal Mapping**: Creates a one-to-one correlation between Ethereum addresses and
  Principals within the scope of the current application.
- **Timebound Sessions**: Allows developers to set expiration times for sessions, enhancing security and control.

## Integration overview

See the [ic-siwe-react-demo-rust](https://github.com/kristoferlund/ic-siwe-react-demo-rust) for a complete example
of how to integrate the `ic_siwe_provider` canister into an IC application. The easiest way to get started is to
fork the demo and modify it to suit your needs.

The [integration tests](https://github.com/kristoferlund/ic-siwe/blob/main/packages/ic_siwe_provider/tests/integration_tests.rs)
for the `ic_siwe_provider` canister also provide a good overview of how to integrate the canister into an IC application.

See [README.md](../README.md) for more information.
 */
use ic_cdk::api::set_certified_data;
use ic_certified_map::{fork_hash, labeled_hash, AsHashTree, Hash, RbTree};
use ic_siwe::signature_map::SignatureMap;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Blob,
    DefaultMemoryImpl, StableBTreeMap,
};
use std::cell::RefCell;

pub mod service;

pub const LABEL_ASSETS: &[u8] = b"http_assets";
pub const LABEL_SIG: &[u8] = b"sig";

pub(crate) type AssetHashes = RbTree<&'static str, Hash>;

pub(crate) struct State {
    pub signature_map: RefCell<SignatureMap>,
    pub asset_hashes: RefCell<AssetHashes>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            signature_map: RefCell::new(SignatureMap::default()),
            asset_hashes: RefCell::new(AssetHashes::default()),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct Settings {
    pub disable_eth_to_principal_mapping: bool,
    pub disable_principal_to_eth_mapping: bool,
}

thread_local! {
    static STATE: State = State::default();

    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static SETTINGS: RefCell<Settings> = const { RefCell::new(Settings {
        disable_eth_to_principal_mapping: false,
        disable_principal_to_eth_mapping: false,
    }) };

    static PRINCIPAL_ADDRESS: RefCell<StableBTreeMap<Blob<29>, [u8;20], VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    static ADDRESS_PRINCIPAL: RefCell<StableBTreeMap<[u8;20], Blob<29>, VirtualMemory<DefaultMemoryImpl>>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
        )
    );
}

pub(crate) fn update_root_hash(asset_hashes: &AssetHashes, signature_map: &SignatureMap) {
    let prefixed_root_hash = fork_hash(
        &labeled_hash(LABEL_ASSETS, &asset_hashes.root_hash()),
        &labeled_hash(LABEL_SIG, &signature_map.root_hash()),
    );
    set_certified_data(&prefixed_root_hash[..]);
}
