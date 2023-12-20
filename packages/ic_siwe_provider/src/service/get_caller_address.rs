use ic_cdk::query;
use serde_bytes::ByteBuf;

use super::get_address::get_address;

#[query]
fn get_caller_address() -> Result<String, String> {
    let principal = ic_cdk::caller();
    get_address(ByteBuf::from(principal.as_slice().to_vec()))
}
