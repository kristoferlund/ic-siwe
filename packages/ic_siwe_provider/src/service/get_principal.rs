use ic_cdk::query;
use ic_siwe::eth::EthAddress;
use serde_bytes::ByteBuf;

use crate::ADDRESS_PRINCIPAL;

/// Retrieves the principal associated with the given Ethereum address.
///
/// # Arguments
/// * `address` - The EIP-55-compliant Ethereum address.
///
/// # Returns
/// * `Ok(ByteBuf)` - The principal if found.
/// * `Err(String)` - An error message if the address cannot be converted or no principal is found.
#[query]
fn get_principal(address: String) -> Result<ByteBuf, String> {
    // Create an EthAddress from the string. This validates the address.
    let address = EthAddress::new(&address)?;

    ADDRESS_PRINCIPAL.with(|ap| {
        ap.borrow().get(&address.as_byte_array()).map_or(
            Err("No principal found for the given address".to_string()),
            |p| Ok(ByteBuf::from(p.as_ref().to_vec())),
        )
    })
}
