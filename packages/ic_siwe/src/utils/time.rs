#[cfg(not(test))]
pub(crate) fn get_current_time() -> u64 {
    // This code is used in production, where ic_cdk::api::time() is available
    ic_cdk::api::time()
}

#[cfg(test)]
pub(crate) fn get_current_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}
