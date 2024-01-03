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

/// A builder for creating `Settings` instances.
///
/// This builder allows for a flexible and clear way of setting up SIWE settings.
pub struct SettingsBuilder {
    settings: Settings,
}

impl SettingsBuilder {
    /// Creates a new `SettingsBuilder` with specified domain and uri.
    ///
    /// # Parameters
    ///
    /// * `domain` - The domain for SIWE.
    /// * `uri` - The URI for SIWE.
    ///
    /// # Returns
    ///
    /// A new instance of `SettingsBuilder`.
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

    pub fn chain_id(mut self, chain_id: u32) -> Self {
        self.settings.chain_id = chain_id;
        self
    }

    pub fn scheme<S: Into<String>>(mut self, scheme: S) -> Self {
        self.settings.scheme = scheme.into();
        self
    }

    pub fn statement<S: Into<String>>(mut self, statement: S) -> Self {
        self.settings.statement = statement.into();
        self
    }

    pub fn sign_in_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.sign_in_expires_in = expires_in;
        self
    }

    pub fn session_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.session_expires_in = expires_in;
        self
    }

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
