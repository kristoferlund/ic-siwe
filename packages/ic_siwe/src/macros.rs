/// A macro to access global `Settings` conveniently within a closure.
///
/// This macro is designed to provide easy and safe access to the globally configured `Settings`.
/// It ensures that the settings are initialized before access and provides them to a user-defined closure for further processing.
///
/// # Examples
///
/// Basic usage:
///
/// ```text
/// with_settings!(|settings: &Settings| {
///     // You can access the settings here
///     println!("Current domain: {}", settings.domain);
/// });
/// ```
///
/// This macro will pass the global `Settings` instance to the closure, allowing you to use the settings without manually fetching them.
#[macro_export]
macro_rules! with_settings {
    ($body:expr) => {
        $crate::SETTINGS.with_borrow(|s| {
            let settings = s
                .as_ref()
                .unwrap_or_else(|| ic_cdk::trap("Settings are not initialized."));
            #[allow(clippy::redundant_closure_call)]
            $body(settings)
        })
    };
}
