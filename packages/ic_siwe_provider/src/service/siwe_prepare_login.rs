use candid::CandidType;
use ic_cdk::update;
use ic_siwe::eth::EthAddress;

#[derive(CandidType)]
struct PrepareLoginOkResponse {
    siwe_message: String,
    nonce: String,
}

/// Prepare the login by generating a challenge (the SIWE message) and returning it to the caller.
///
/// # Arguments
/// * `address` (String): The Ethereum address of the user to prepare the login for.
///
/// # Returns
/// * `Ok(PrepareLoginOkResponse)`: Contains the SIWE message and the nonce used in the login function.
/// * `Err(String)`: An error message if the address is invalid.
#[update]
fn siwe_prepare_login(address: String) -> Result<PrepareLoginOkResponse, String> {
    // Create an EthAddress from the string. This validates the address.
    let address = EthAddress::new(&address)?;

    match ic_siwe::login::prepare_login(&address) {
        Ok(m) => Ok(PrepareLoginOkResponse {
            siwe_message: m.0.into(),
            nonce: m.1,
        }),
        Err(e) => Err(e.into()),
    }
}
