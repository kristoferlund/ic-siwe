use ic_cdk::query;
use ic_siwe::eth::{bytes_to_eth_address, convert_to_eip55};
use ic_stable_structures::storable::Blob;
use serde_bytes::ByteBuf;

use crate::PRINCIPAL_ADDRESS;

/// Retrieves the Ethereum address associated with a given IC principal.
///
/// # Arguments
/// * `principal` - A `ByteBuf` containing the principal's bytes, expected to be 29 bytes.
///
/// # Returns
/// * `Ok(String)` - The EIP-55-compliant Ethereum address if found.
/// * `Err(String)` - An error message if the principal cannot be converted or no address is found.
#[query]
pub(crate) fn get_address(principal: ByteBuf) -> Result<String, String> {
    let principal: Blob<29> = principal
        .as_ref()
        .try_into()
        .map_err(|_| "Failed to convert ByteBuf to Blob<29>")?;

    let address = PRINCIPAL_ADDRESS.with(|pa| {
        pa.borrow().get(&principal).map_or(
            Err("No address found for the given principal".to_string()),
            |a| Ok(bytes_to_eth_address(&a)),
        )
    })?;

    convert_to_eip55(&address)
}
