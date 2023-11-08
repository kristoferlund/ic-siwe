#[cfg(not(test))]
pub fn generate_nonce() -> Result<[u8; 10], String> {
    use crate::RNG;
    use rand_chacha::rand_core::RngCore;

    let mut buf = [0u8; 10];
    RNG.with_borrow_mut(|rng| rng.as_mut().unwrap().fill_bytes(&mut buf));
    Ok(buf)
}

#[cfg(test)]
pub fn generate_nonce() -> Result<[u8; 10], String> {
    Ok([0u8; 10])
}
