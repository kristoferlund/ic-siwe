use ic_cdk::query;
use ic_siwe::eth::eth_address_to_bytes;
use serde_bytes::ByteBuf;

use crate::ADDRESS_PRINCIPAL;

#[query]
fn get_principal(address: String) -> Result<ByteBuf, String> {
    let address: [u8; 20] = eth_address_to_bytes(&address)
        .map_err(|_| format!("Invalid Ethereum address: {}", address))?
        .try_into()
        .map_err(|_| format!("Invalid Ethereum address: {}", address))?;

    ADDRESS_PRINCIPAL.with(|ap| {
        ap.borrow().get(&address).map_or(
            Err("No principal found for the given address".to_string()),
            |p| Ok(ByteBuf::from(p.as_ref().to_vec())),
        )
    })
}
