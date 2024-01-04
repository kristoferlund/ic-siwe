use candid::Principal;
use url::Url;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_STATEMENT: &str = "SIWE Fields:";
const DEFAULT_CHAIN_ID: u32 = 1; // Ethereum mainnet
const DEFAULT_SIGN_IN_EXPIRES_IN: u64 = 60 * 5 * 1_000_000_000; // 5 minutes
const DEFAULT_SESSION_EXPIRES_IN: u64 = 30 * 60 * 1_000_000_000; // 30 minutes

/// Represents the settings for initializing SIWE.
///
/// This struct is used to configure SIWE (Sign-In With Ethereum) functionality.
/// It includes settings such as domain, scheme, statement, and expiration times for sessions and sign-ins.
///
/// Use the [`SettingsBuilder`] to create a new instance of `Settings` to validate inputs and use default values.
///
/// The SIWE library needs to be initialized with a `Settings` instance before it can be used. Call the [`crate::init()`] function
/// to initialize the library.
#[derive(Default, Debug, Clone)]
pub struct Settings {
    pub domain: String,
    pub uri: String,
    pub salt: String,
    pub chain_id: u32,
    pub scheme: String,
    pub statement: String,

    // The TTL for a sign-in message in nanoseconds. After this time, the sign-in message will be pruned.
    pub sign_in_expires_in: u64,

    // The TTL for a session in nanoseconds.
    pub session_expires_in: u64,

    // The list of canisters for which the identity delegation is allowed. Defaults to None, which means
    // that the delegation is allowed for all canisters.
    pub targets: Option<Vec<Principal>>,
}

/// A builder for creating `Settings` instances.
///
/// This builder provides a flexible way to configure and initialize the settings for SIWE (Sign-In With Ethereum).
/// It allows for setting various parameters like domain, URI, salt, and expiration times for sessions and sign-ins.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// use your_crate::{SettingsBuilder, Settings};
///
/// let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
///     .chain_id(1)  // Ethereum mainnet
///     .scheme("https")
///     .statement("Sign in to access your account")
///     .sign_in_expires_in(300_000_000_000)  // 5 minutes in nanoseconds
///     .session_expires_in(1_800_000_000_000); // 30 minutes in nanoseconds
///
/// let settings: Settings = builder.build().expect("Failed to create settings");
/// ```
///
/// This will create a `Settings` instance with the specified domain, URI, salt, and other configuration parameters.
pub struct SettingsBuilder {
    settings: Settings,
}

impl SettingsBuilder {
    /// Creates a new `SettingsBuilder` with the specified domain, URI, and salt.
    /// This is the starting point for building a `Settings` struct.
    ///
    /// # Parameters
    ///
    /// * `domain`: The domain from where the frontend that uses SIWE is served.
    /// * `uri`: The full URI, potentially including port number of the frontend that uses SIWE.
    /// * `salt`: The salt is used when generating the seed that uniquely identifies each user principal.
    pub fn new<S: Into<String>, T: Into<String>, U: Into<String>>(
        domain: S,
        uri: T,
        salt: U,
    ) -> Self {
        SettingsBuilder {
            settings: Settings {
                domain: domain.into(),
                uri: uri.into(),
                salt: salt.into(),
                chain_id: DEFAULT_CHAIN_ID,
                scheme: DEFAULT_SCHEME.to_string(),
                statement: DEFAULT_STATEMENT.to_string(),
                sign_in_expires_in: DEFAULT_SIGN_IN_EXPIRES_IN,
                session_expires_in: DEFAULT_SESSION_EXPIRES_IN,
                targets: None,
            },
        }
    }

    /// Sets the Ethereum chain ID for ic-siwe.
    /// The `chain_id` is used to specify the Ethereum network (e.g., 1 for mainnet). Defaults to 1 (Ethereum mainnet).
    pub fn chain_id(mut self, chain_id: u32) -> Self {
        self.settings.chain_id = chain_id;
        self
    }

    /// The scheme used to serve the frontend that uses SIWE.
    /// The `scheme` is typically "http" or "https", defining the protocol part of the URI. Defaults to "https".
    pub fn scheme<S: Into<String>>(mut self, scheme: S) -> Self {
        self.settings.scheme = scheme.into();
        self
    }

    /// The `statement` is a message or declaration, often presented to the user by the Ethereum wallet
    /// during the sign-in process. Defaults to "SIWE Fields:".
    pub fn statement<S: Into<String>>(mut self, statement: S) -> Self {
        self.settings.statement = statement.into();
        self
    }

    /// Sign in messages are valid for a limited time, after which they expire. The `sign_in_expires_in` value is
    /// the time-to-live (TTL) for a sign-in message in nanoseconds. Defaults to 5 minutes.
    pub fn sign_in_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.sign_in_expires_in = expires_in;
        self
    }

    /// Sessions (as represented by delegete identities) are valid for a limited time, after which they expire.
    /// The `session_expires_in` value is the time-to-live (TTL) for a session in nanoseconds. Defaults to 30 minutes.
    pub fn session_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.session_expires_in = expires_in;
        self
    }

    /// The `targets` is a list of `Principal`s representing the canisters where the delegated identity can be used to
    /// authenticate the user. Defaults to None, which means that the delegation is allowed for any canister.
    pub fn targets(mut self, targets: Vec<Principal>) -> Self {
        self.settings.targets = Some(targets);
        self
    }

    pub fn build(self) -> Result<Settings, String> {
        validate_domain(&self.settings.scheme, &self.settings.domain)?;
        validate_uri(&self.settings.uri)?;
        validate_salt(&self.settings.salt)?;
        validate_chain_id(self.settings.chain_id)?;
        validate_scheme(&self.settings.scheme)?;
        validate_statement(&self.settings.statement)?;
        validate_sign_in_expires_in(self.settings.sign_in_expires_in)?;
        validate_session_expires_in(self.settings.session_expires_in)?;

        Ok(self.settings)
    }
}

fn validate_domain(scheme: &str, domain: &str) -> Result<String, String> {
    let url_str = format!("{}://{}", scheme, domain);
    let parsed_url = Url::parse(&url_str).map_err(|_| String::from("Invalid domain"))?;
    if !parsed_url.has_authority() {
        Err(String::from("Invalid domain"))
    } else {
        Ok(parsed_url.host_str().unwrap().to_string())
    }
}

fn validate_uri(uri: &str) -> Result<String, String> {
    let parsed_uri = Url::parse(uri).map_err(|_| String::from("Invalid URI"))?;
    if !parsed_uri.has_host() {
        Err(String::from("Invalid URI"))
    } else {
        Ok(uri.to_string())
    }
}

fn validate_salt(salt: &str) -> Result<String, String> {
    if salt.is_empty() {
        return Err(String::from("Salt cannot be empty"));
    }
    Ok(salt.to_string())
}

fn validate_chain_id(chain_id: u32) -> Result<u32, String> {
    if chain_id == 0 {
        return Err(String::from("Chain ID must be greater than 0"));
    }
    Ok(chain_id)
}

fn validate_scheme(scheme: &str) -> Result<String, String> {
    if scheme == "http" || scheme == "https" {
        return Ok(scheme.to_string());
    }
    Err(String::from("Invalid scheme"))
}

fn validate_statement(statement: &str) -> Result<String, String> {
    if statement.contains('\n') {
        return Err(String::from("Invalid statement"));
    }
    Ok(statement.to_string())
}

fn validate_sign_in_expires_in(expires_in: u64) -> Result<u64, String> {
    if expires_in == 0 {
        return Err(String::from("Sign in expires in must be greater than 0"));
    }
    Ok(expires_in)
}

fn validate_session_expires_in(expires_in: u64) -> Result<u64, String> {
    if expires_in == 0 {
        return Err(String::from("Session expires in must be greater than 0"));
    }
    Ok(expires_in)
}

/// A macro to access global `Settings` conveniently within a closure.
///
/// This macro is designed to provide easy and safe access to the globally configured `Settings`.
/// It ensures that the settings are initialized before access and provides them to a user-defined closure for further processing.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// use your_crate::{with_settings, Settings};
///
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
