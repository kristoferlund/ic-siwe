use ic_cdk::update;

// Prepare the login by generating a challenge (the SIWE message) and returning it to the caller.
#[update]
fn siwe_prepare_login(address: String) -> Result<String, String> {
    match ic_siwe::login::prepare_login(&address) {
        Ok(m) => Ok(m.into()),   // Converts SiweMessage to String
        Err(e) => Err(e.into()), // Converts EthError to String
    }
}
