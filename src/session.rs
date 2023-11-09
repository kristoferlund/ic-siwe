use candid::Principal;

use crate::SESSION_MESSAGES;

pub fn get_address(principal: Principal) -> Result<String, String> {
    SESSION_MESSAGES.with_borrow(|map| {
        map.get(principal.as_slice())
            .map(|message| message.address.clone())
            .ok_or_else(|| String::from("No session found for the given principal"))
    })
}
