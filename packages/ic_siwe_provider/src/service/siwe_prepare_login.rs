use crate::ensure_authenticated;
use ic_cdk::{api::msg_caller, update};
use ic_siwe::eth::EthAddress;

/// Prepare the login by generating a challenge (the SIWE message) and returning it to the caller.
/// This function requires an authenticated caller (not anonymous).
///
/// # Arguments
/// * `address` (String): The Ethereum address of the user to prepare the login for.
///
/// # Returns
/// * `Ok(String)`: The SIWE message as a string.
/// * `Err(String)`: An error message if the address is invalid or caller is anonymous.
#[update(guard = "ensure_authenticated")]
fn siwe_prepare_login(address: String) -> Result<String, String> {
    // Create an EthAddress from the string. This validates the address.
    let address = EthAddress::new(&address)?;

    match ic_siwe::login::prepare_login(&address, &msg_caller()) {
        Ok(message) => Ok(message.into()),
        Err(e) => Err(e.into()),
    }
}
