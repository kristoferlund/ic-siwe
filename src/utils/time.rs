#[cfg(not(test))]
pub fn get_current_time() -> u64 {
    // This code is used in production, where ic_cdk::api::time() is available
    ic_cdk::api::time()
}

#[cfg(test)]
pub fn get_current_time() -> u64 {
    // In tests, return a fixed time or a mock time as needed
    // For example, you might have a static variable in your tests that determines the mock time
    123456789 // replace with a suitable way to get mock time for your tests
}
