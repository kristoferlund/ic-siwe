use crate::types::settings::get_settings;

pub fn create_identity_message(address: String) -> Result<String, String> {
    let settings = get_settings()?;

    Ok(format!(
    "{domain} wants to create an identity on the Internet Computer based on Ethereum account:\n\n\
    {address}\n\n\
    ",
    domain = settings.domain,
  ))
}
