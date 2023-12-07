/// Validates an Ethereum address by checking its length and hex encoding.
pub(crate) fn validate_address(address: &str) -> Result<(), String> {
    if !address.starts_with("0x") || address.len() != 42 {
        return Err(String::from(
            "Invalid Ethereum address: Must start with '0x' and be 42 characters long",
        ));
    }

    hex::decode(&address[2..]).map_err(|_| "Invalid Ethereum address: Hex decoding failed")?;
    Ok(())
}

pub(crate) fn validate_signature(signature: &str) -> Result<(), String> {
    if !signature.starts_with("0x") || signature.len() != 132 {
        return Err(String::from(
            "Invalid signature: Must start with '0x' and be 132 characters long",
        ));
    }

    hex::decode(&signature[2..]).map_err(|_| "Invalid signature: Hex decoding failed")?;
    Ok(())
}
