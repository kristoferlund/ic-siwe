use crate::{create_identity_message, utils::eth::recover_address};

pub fn verify_identity_signature(signature: String, address: String) -> Result<String, String> {
    let message = create_identity_message(address.clone())?;

    let recovered_address = recover_address(&signature, &message)?;
    if recovered_address != address {
        return Err("Signature verification failed".to_string());
    }
    Ok(address)
}
