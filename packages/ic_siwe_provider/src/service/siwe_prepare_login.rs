use ic_cdk::update;
use ic_siwe::eth::EthAddress;

// Prepare the login by generating a challenge (the SIWE message) and returning it to the caller.
#[update]
fn siwe_prepare_login(address: String) -> Result<String, String> {
    // Create an EthAddress from the string. This validates the address.
    let address = EthAddress::new(&address)?;

    match ic_siwe::login::prepare_login(&address) {
        Ok(m) => Ok(m.into()),   // Converts SiweMessage to String
        Err(e) => Err(e.into()), // Converts EthError to String
    }
}
