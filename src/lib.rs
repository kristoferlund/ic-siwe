//! # IC_SIWE Crate
//!
//! `ic_siwe` is a Rust crate designed to facilitate Sign-In With Ethereum (SIWE) on the Internet Computer.
//! It provides utilities for creating and validating SIWE messages, as well as initializing SIWE settings.
//!
//! This crate is intended to be used in both backend and frontend canisters, providing a seamless way to integrate
//! Ethereum-based authentication into your Internet Computer applications.
//!
//! ## Features
//!
//! - Initialization of SIWE settings
//! - Creation of SIWE messages
//! - Validation of SIWE fields
//! - Custom response types for inter-canister communication
//!
//! ## Usage
//!
//! Add `ic_siwe` as a dependency in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! ic_siwe = "0.1.0"
//! ```
//!
//! Import the crate and use its functionalities:
//!
//! ```rust
//! extern crate ic_siwe;
//!
//! use ic_siwe::{init, create_message};
//! ```
//!
//! For more details, refer to the specific module documentation.

#[cfg(not(test))]
use rand_chacha::rand_core::RngCore;

use rand_chacha::ChaCha20Rng;
use siwe_message::SiweMessage;
use siwe_settings::SiweSettings;
use std::{cell::RefCell, collections::HashMap};

pub mod create_message;
pub mod init;
pub mod login;
pub mod siwe_message;
pub mod siwe_settings;

pub use create_message::{create_message, create_message_as_erc_4361};
pub use init::init;
pub use login::login;

thread_local! {
  static SETTINGS: RefCell<Option<SiweSettings>> = RefCell::new(None);
  static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);
  static SIWE_MESSAGES: RefCell<HashMap<Vec<u8>, SiweMessage>> = RefCell::new(HashMap::new());
}

#[cfg(not(test))]
fn generate_nonce() -> Result<[u8; 10], String> {
    let mut buf = [0u8; 10];
    RNG.with_borrow_mut(|rng| rng.as_mut().unwrap().fill_bytes(&mut buf));
    Ok(buf)
}

#[cfg(test)]
fn generate_nonce() -> Result<[u8; 10], String> {
    Ok([0u8; 10])
}
