use ic_cdk::update;

// Prepare the login by generating a challenge (the SIWE message) and returning it to the caller.
#[update]
fn prepare_login(address: String) -> Result<String, String> {
    ic_siwe::login::prepare_login(&address).map(|m| m.into())
}
