use crate::ensure_authenticated;
use ic_cdk::{api::msg_caller, update};
use ic_siwe::eth::EthAddress;

/// Prepare the login by generating a challenge (the SIWE message) and returning it to the caller.
///
/// # Arguments
/// * `address` (String): The Ethereum address of the user to prepare the login for.
///
/// # Returns
/// * `Ok(PrepareLoginOkResponse)`: Contains the SIWE message and the nonce used in the login function.
/// * `Err(String)`: An error message if the address is invalid.
#[update(guard = "ensure_authenticated")]
fn siwe_prepare_login(address: String) -> Result<String, String> {
    // Create an EthAddress from the string. This validates the address.
    let address = EthAddress::new(&address)?;

    match ic_siwe::login::prepare_login(&address, &msg_caller()) {
        Ok(message) => Ok(message.into()),
        Err(e) => Err(e.into()),
    }
}
