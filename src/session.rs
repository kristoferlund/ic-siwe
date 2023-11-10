use candid::Principal;

use crate::{types::siwe_message::SiweMessage, SESSION_MESSAGES};

pub fn get_address(principal: Principal) -> Result<String, String> {
    SESSION_MESSAGES.with_borrow(|map| {
        map.get(principal.as_slice())
            .map(|message| message.address.clone())
            .ok_or_else(|| String::from("No session found for the given principal"))
    })
}

pub fn session(principal: Principal) -> Result<SiweMessage, String> {
    SESSION_MESSAGES.with_borrow(|map| {
        map.get(principal.as_slice())
            .cloned()
            .ok_or_else(|| String::from("No session found for the given principal"))
    })
}

// Session
// siwe_message: SiweMessage,
// created_at: u64,
// max_age: u64,

// session.touch - Updates the .maxAge property.
// session.destroy
// session.save

// Store
// store.all
// store.destroy
// store.clear
// store.length
// store.get
