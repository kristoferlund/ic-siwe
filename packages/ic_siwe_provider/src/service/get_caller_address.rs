use ic_cdk::query;
use serde_bytes::ByteBuf;

use crate::SETTINGS;

use super::get_address::get_address;

/// Retrieves the Ethereum address associated with the caller.
/// This is a convenience function that calls `get_address` with the caller's principal.
/// See `get_address` for more information.
///
/// # Returns
/// * `Ok(String)` - The EIP-55-compliant Ethereum address if found.
/// * `Err(String)` - An error message if the principal cannot be converted or no address is found.
#[query]
fn get_caller_address() -> Result<String, String> {
    SETTINGS.with_borrow(|s| {
        if s.disable_principal_to_eth_mapping {
            return Err("Principal to Ethereum address mapping is disabled".to_string());
        }
        Ok(())
    })?;

    let principal = ic_cdk::caller();
    get_address(ByteBuf::from(principal.as_slice().to_vec()))
}
