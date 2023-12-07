//! IC_SIWE Crate
//!
//! This crate facilitates the integration of Sign-In With Ethereum (SIWE) in Internet Computer (IC) applications.
//! It provides utilities for creating and validating SIWE messages, initializing SIWE settings,
//! and is suitable for both backend and frontend canisters in the IC ecosystem.
//!
//! ## Features
//!
//! - Initialization of SIWE settings
//! - Creation and validation of SIWE messages
//! - Support for custom response types in inter-canister communication
//!
//! ## Usage
//!
//! To use `ic_siwe` in your project, add it as a dependency in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! ic_siwe = "0.1.0"
//! ```
//!
//! Then, import the crate and utilize its functions in your canister:
//!
//! ```rust
//! extern crate ic_siwe;
//! use ic_siwe::{init, create_message};
//! ```
//!
//! ## Example: Integrating IC_SIWE into an IC Canister
//!
//! Below is a simplified example showing how to integrate `ic_siwe` into an Internet Computer canister:
//!
//! ```rust
//! use ic_siwe::{login, create_message_as_erc_4361, init, SettingsBuilder};
//! use std::time::Duration;
//!
//! // Sample function to initialize SIWE settings
//! fn siwe_init() {
//!     let settings = SettingsBuilder::new("your-domain.com", "https://your-domain.com")
//!         .scheme("https")
//!         .statement("Sign in with your Ethereum account")
//!         .sign_in_expires_in(Duration::from_secs(300).as_nanos() as u64) // 5 minutes
//!         .build()
//!         .expect("Failed to build settings");
//!     init(settings).expect("Failed to initialize SIWE");
//! }
//!
//! // Function to handle SIWE login in your canister
//! #[update]
//! async fn siwe_login(signature: String, address: String) -> Result<String, String> {
//!     let user_address = login(signature, address).await?;
//!     // Additional logic to handle user session
//!     Ok(user_address)
//! }
//!
//! // Function to create a SIWE message
//! #[update]
//! fn siwe_create_message(address: String) -> Result<String, String> {
//!     create_message_as_erc_4361(address)
//! }
//!
//! // Canister initialization
//! #[init]
//! fn init() {
//!     siwe_init();
//! }
//!
//! // Canister upgrade handling
//! #[post_upgrade]
//! fn upgrade() {
//!     siwe_init();
//! }
//! ```
//!
//! This example illustrates how to set up SIWE in an IC canister. It includes initializing SIWE settings, creating a SIWE message, and handling the login process using Ethereum signatures and addresses.
//!
//! Remember to replace `"your-domain.com"` and `"https://your-domain.com"` with your actual domain and URI. The `siwe_login` function demonstrates how to process a login request, and `siwe_create_message` shows how to create a SIWE message for the frontend to present to the user.
//!
//! ## Testing
//!
//! Here is a sample test scenario for a successful login using the `ic_siwe` crate:
//!
//! ```rust
//! #[tokio::test]
//! async fn test_successful_login() {
//!     // Sample setup for testing
//!     // ...
//!     let wallet = LocalWallet::new(&mut rand::thread_rng());
//!     let h160 = wallet.address();
//!     let address = to_checksum(&h160, None);
//!     let message = create_message(address.clone()).unwrap().to_erc_4361();
//!     let signature = wallet.sign_message(message).await.unwrap().to_string();
//!     let result = login(signature, address).await;
//!     assert!(result.is_ok());
//! }
//! ```
//!
//! This test demonstrates a successful login process using the `ic_siwe` crate's `login` function, simulating an Ethereum wallet signature verification.

mod get_delegation;
mod init;
mod login;
mod prepare_login;
mod types;
mod utils;

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
