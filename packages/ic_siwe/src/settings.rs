use candid::Principal;
use url::Url;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_STATEMENT: &str = "SIWE Fields:";
const DEFAULT_CHAIN_ID: u32 = 1; // Ethereum mainnet
const DEFAULT_SIGN_IN_EXPIRES_IN: u64 = 60 * 5 * 1_000_000_000; // 5 minutes
const DEFAULT_SESSION_EXPIRES_IN: u64 = 30 * 60 * 1_000_000_000; // 30 minutes

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeFeature {
    // Enabling this feature will include the app frontend URI as part of the identity seed.
    IncludeUriInSeed,
}

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
    /// The domain from where the frontend that uses SIWE is served.
    pub domain: String,

    /// The full URI, potentially including port number of the frontend that uses SIWE.
    pub uri: String,

    /// The salt is used when generating the seed that uniquely identifies each user principal. The salt can only contain
    /// printable ASCII characters.
    pub salt: String,

    /// The Ethereum chain ID for ic-siwe, defaults to 1 (Ethereum mainnet).
    pub chain_id: u32,

    // The scheme used to serve the frontend that uses SIWE. Defaults to "https".
    pub scheme: String,

    /// The statement is a message or declaration, often presented to the user by the Ethereum wallet
    pub statement: String,

    /// The TTL for a sign-in message in nanoseconds. After this time, the sign-in message will be pruned.
    pub sign_in_expires_in: u64,

    /// The TTL for a session in nanoseconds.
    pub session_expires_in: u64,

    /// The list of canisters for which the identity delegation is allowed. Defaults to None, which means
    /// that the delegation is allowed for all canisters.
    pub targets: Option<Vec<Principal>>,

    // Optional runtime features that can be enabled for SIWE.
    pub runtime_features: Option<Vec<RuntimeFeature>>,
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
/// use ic_siwe::settings::{Settings, SettingsBuilder};
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
                runtime_features: None,
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

    /// Optional runtime features customize the behavior of ic-siwe.
    pub fn runtime_features(mut self, features: Vec<RuntimeFeature>) -> Self {
        self.settings.runtime_features = Some(features);
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
        validate_targets(&self.settings.targets)?;

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
    // Salt can only contain printable ASCII characters
    if salt.chars().any(|c| !c.is_ascii() || !c.is_ascii_graphic()) {
        return Err(String::from("Invalid salt"));
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

fn validate_targets(targets: &Option<Vec<Principal>>) -> Result<Option<Vec<Principal>>, String> {
    if let Some(targets) = targets {
        if targets.is_empty() {
            return Err(String::from("Targets cannot be empty"));
        }

        // There is a limit of 1000 targets
        if targets.len() > 1000 {
            return Err(String::from("Too many targets"));
        }

        // Duplicate targets are not allowed
        let mut targets_clone = targets.clone();
        targets_clone.sort();
        targets_clone.dedup();
        if targets_clone.len() != targets.len() {
            return Err(String::from("Duplicate targets are not allowed"));
        }
    }
    Ok(targets.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;

    // Test successful settings creation with default values
    #[test]
    fn test_successful_settings_creation_defaults() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt");
        let settings = builder
            .build()
            .expect("Failed to create settings with defaults");
        assert_eq!(settings.domain, "example.com");
        assert_eq!(settings.uri, "http://example.com");
        assert_eq!(settings.salt, "some_salt");
        assert_eq!(settings.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(settings.scheme, DEFAULT_SCHEME);
        assert_eq!(settings.statement, DEFAULT_STATEMENT);
        assert_eq!(settings.sign_in_expires_in, DEFAULT_SIGN_IN_EXPIRES_IN);
        assert_eq!(settings.session_expires_in, DEFAULT_SESSION_EXPIRES_IN);
        assert!(settings.targets.is_none());
    }

    // Test successful settings creation with custom values
    #[test]
    fn test_successful_settings_creation_custom() {
        let targets = vec![Principal::anonymous()];
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .chain_id(3)
            .scheme("http")
            .statement("Custom statement")
            .sign_in_expires_in(10_000_000_000)
            .session_expires_in(20_000_000_000)
            .targets(targets.clone());
        let settings = builder
            .build()
            .expect("Failed to create settings with custom values");
        assert_eq!(settings.chain_id, 3);
        assert_eq!(settings.scheme, "http");
        assert_eq!(settings.statement, "Custom statement");
        assert_eq!(settings.sign_in_expires_in, 10_000_000_000);
        assert_eq!(settings.session_expires_in, 20_000_000_000);
        assert_eq!(settings.targets, Some(targets));
    }

    // Test empty salt
    #[test]
    fn test_empty_salt() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "");
        assert!(builder.build().is_err());
    }

    // Test invalid chain ID
    #[test]
    fn test_invalid_chain_id() {
        let builder =
            SettingsBuilder::new("example.com", "http://example.com", "some_salt").chain_id(0);
        assert!(builder.build().is_err());
    }

    // Test invalid scheme
    #[test]
    fn test_invalid_scheme() {
        let builder =
            SettingsBuilder::new("example.com", "http://example.com", "some_salt").scheme("ftp");
        assert!(builder.build().is_err());
    }

    // Test invalid statement
    #[test]
    fn test_invalid_statement() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .statement("Invalid\nStatement");
        assert!(builder.build().is_err());
    }

    // Test sign in expires in is zero
    #[test]
    fn test_sign_in_expires_in_zero() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .sign_in_expires_in(0);
        assert!(builder.build().is_err());
    }

    // Test session expires in is zero
    #[test]
    fn test_session_expires_in_zero() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .session_expires_in(0);
        assert!(builder.build().is_err());
    }

    // Test empty targets
    #[test]
    fn test_empty_targets() {
        let builder =
            SettingsBuilder::new("example.com", "http://example.com", "some_salt").targets(vec![]);
        assert!(builder.build().is_err());
    }

    // Test too many targets
    #[test]
    fn test_too_many_targets() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .targets(vec![Principal::anonymous(); 1001]);
        assert!(builder.build().is_err());
    }

    // Test duplicate targets
    #[test]
    fn test_duplicate_targets() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .targets(vec![Principal::anonymous(), Principal::anonymous()]);
        assert!(builder.build().is_err());
    }

    // Test various valid domain formats
    #[test]
    fn test_valid_domain_formats() {
        let domains = vec!["example.com", "sub.domain.com", "example.co.uk"];
        for domain in domains {
            let builder = SettingsBuilder::new(domain, "http://example.com", "some_salt");
            assert!(builder.build().is_ok(), "Failed with domain: {}", domain);
        }
    }

    // Test invalid domain formats
    #[test]
    fn test_invalid_domain_formats() {
        let domains = vec![""];
        for domain in domains {
            let builder = SettingsBuilder::new(domain, "http://example.com", "some_salt");
            assert!(
                builder.build().is_err(),
                "Should fail with domain: {}",
                domain
            );
        }
    }

    // Test URIs with different valid formats
    #[test]
    fn test_valid_uri_formats() {
        let uris = vec!["http://example.com", "https://example.com:8080/path"];
        for uri in uris {
            let builder = SettingsBuilder::new("example.com", uri, "some_salt");
            assert!(builder.build().is_ok(), "Failed with URI: {}", uri);
        }
    }

    // Test invalid URIs
    #[test]
    fn test_invalid_uris() {
        let uris = vec!["", "just_string"];
        for uri in uris {
            let builder = SettingsBuilder::new("example.com", uri, "some_salt");
            assert!(builder.build().is_err(), "Should fail with URI: {}", uri);
        }
    }

    #[test]
    fn test_chain_id_zero() {
        let builder =
            SettingsBuilder::new("example.com", "http://example.com", "some_salt").chain_id(0);
        assert!(builder.build().is_err(), "Chain ID zero should fail");
    }

    // Test URI with Port Numbers
    #[test]
    fn test_uri_with_port_numbers() {
        let builder = SettingsBuilder::new("example.com", "http://example.com:8080", "some_salt");
        assert!(builder.build().is_ok());
    }

    // Test Valid Salt Lengths
    #[test]
    fn test_valid_salt_lengths() {
        for len in [1, 10, 100].iter() {
            let salt = "a".repeat(*len);
            let builder = SettingsBuilder::new("example.com", "http://example.com", &salt);
            assert!(builder.build().is_ok(), "Failed with salt length: {}", len);
        }
    }

    // Test Chain ID Boundary Values
    #[test]
    fn test_chain_id_boundary_values() {
        let max_value = u32::MAX;
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .chain_id(max_value);
        assert!(builder.build().is_ok());
    }

    // Test Scheme Case Sensitivity
    #[test]
    fn test_scheme_case_sensitivity() {
        let builder =
            SettingsBuilder::new("example.com", "http://example.com", "some_salt").scheme("HTTP");
        assert!(builder.build().is_err());
    }

    // Test Statement Length and Content
    #[test]
    fn test_statement_length_and_content() {
        let long_statement = "a".repeat(1000);
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .statement(long_statement);
        assert!(builder.build().is_ok());
    }

    // Test Extreme Expiration Values
    #[test]
    fn test_extreme_expiration_values() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .sign_in_expires_in(1)
            .session_expires_in(u64::MAX);
        assert!(builder.build().is_ok());
    }

    // Test Targets with Various Principal Formats
    #[test]
    fn test_targets_with_various_principal_formats() {
        let targets = vec![
            Principal::anonymous(),
            Principal::from_text("aaaaa-aa").unwrap(),
        ];
        let builder =
            SettingsBuilder::new("example.com", "http://example.com", "some_salt").targets(targets);
        assert!(builder.build().is_ok());
    }

    // Test Multiple Valid and Invalid Combinations
    #[test]
    fn test_multiple_valid_and_invalid_combinations() {
        let builder = SettingsBuilder::new("", "invalid_uri", "")
            .chain_id(0)
            .scheme("ftp");
        assert!(builder.build().is_err());
    }

    // Test Partially Initialized Builder
    #[test]
    fn test_partially_initialized_builder() {
        let builder =
            SettingsBuilder::new("example.com", "http://example.com", "some_salt").scheme("http");
        assert!(builder.build().is_ok());
    }

    // Test Overwriting Default Values
    #[test]
    fn test_overwriting_default_values() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .scheme(DEFAULT_SCHEME)
            .chain_id(DEFAULT_CHAIN_ID);
        assert!(builder.build().is_ok());
    }

    // Test Malformed URIs
    #[test]
    fn test_malformed_uris() {
        let builder = SettingsBuilder::new("example.com", "://missing_protocol.com", "some_salt");
        assert!(builder.build().is_err());
    }

    // Test Invalid Salt Content
    #[test]
    fn test_invalid_salt_content() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "\0invalid_salt");
        assert!(builder.build().is_err());
    }

    // Test Invalid Statement Formats
    #[test]
    fn test_invalid_statement_formats() {
        let builder = SettingsBuilder::new("example.com", "http://example.com", "some_salt")
            .statement("Invalid\nStatement");
        assert!(builder.build().is_err());
    }

    // Test Validating an Empty SettingsBuilder
    #[test]
    fn test_validating_an_empty_settingsbuilder() {
        let builder = SettingsBuilder::new("", "", "");
        assert!(builder.build().is_err());
    }

    // Test Domain with International Characters
    #[test]
    fn test_domain_with_international_characters() {
        let builder = SettingsBuilder::new("xn--exmple-cua.com", "http://example.com", "some_salt");
        assert!(builder.build().is_ok());
    }
}
