use url::Url;

use crate::SETTINGS;

extern crate serde;
extern crate serde_json;

/// Represents the settings for initializing SIWE.
///
/// This struct is used to pass settings to the `init` function for SIWE configuration.
#[derive(Default, Debug, Clone)]
pub struct Settings {
    pub domain: String,
    pub scheme: String,
    pub statement: String,
    pub uri: String,
    pub chain_id: u32,
    pub session_expires_in: u64,
    pub sign_in_expires_in: u64,
}

pub fn get_settings() -> Result<Settings, String> {
    SETTINGS.with_borrow(|settings| {
        settings
            .as_ref()
            .cloned() // Clone the Settings value
            .ok_or_else(|| String::from("Settings are not initialized"))
    })
}

pub struct SettingsBuilder {
    settings: Settings,
}

impl SettingsBuilder {
    pub fn new<S: Into<String>, T: Into<String>>(domain: S, uri: T) -> Self {
        SettingsBuilder {
            settings: Settings {
                domain: domain.into(),
                uri: uri.into(),
                chain_id: 1, // defaults to Ethereum mainnet
                scheme: String::from("https"),
                statement: String::from("SIWE Fields:"),
                session_expires_in: 60 * 60 * 24 * 1_000_000_000, // 24 hours
                sign_in_expires_in: 5 * 60 * 1_000_000_000,       // 5 minutes
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

    pub fn session_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.session_expires_in = expires_in;
        self
    }

    pub fn sign_in_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.sign_in_expires_in = expires_in;
        self
    }

    pub fn build(self) -> Result<Settings, String> {
        validate_domain(&self.settings.scheme, &self.settings.domain)?;
        validate_scheme(&self.settings.scheme)?;
        validate_statement(&self.settings.statement)?;
        validate_uri(&self.settings.uri)?;
        validate_session_expires_in(self.settings.session_expires_in)?;
        validate_sign_in_expires_in(self.settings.sign_in_expires_in)?;

        Ok(self.settings)
    }
}

/// Validates the provided domain based on the given scheme.
///
/// # Parameters
///
/// * `scheme: &str` - The URI scheme associated with the domain.
/// * `domain: &str` - The domain to validate.
///
/// # Returns
///
/// Returns a `Result<String, String>` containing the valid domain or an error message.
fn validate_domain(scheme: &str, domain: &str) -> Result<String, String> {
    let url_str = format!("{}://{}", scheme, domain);
    let parsed_url = Url::parse(&url_str).map_err(|_| String::from("Invalid domain"))?;
    if !parsed_url.has_authority() {
        Err(String::from("Invalid domain"))
    } else {
        Ok(parsed_url.host_str().unwrap().to_string())
    }
}

// Validates the provided URI scheme.
///
/// # Parameters
///
/// * `scheme: &str` - The URI scheme to validate.
///
/// # Returns
///
/// Returns a `Result<String, String>` containing the valid scheme or an error message.
fn validate_scheme(scheme: &str) -> Result<String, String> {
    if scheme == "http" || scheme == "https" {
        return Ok(scheme.to_string());
    }
    Err(String::from("Invalid scheme"))
}

/// Validates the provided statement.
///
/// # Parameters
///
/// * `statement: &str` - The statement to validate.
///
/// # Returns
///
/// Returns a `Result<String, String>` containing the valid statement or an error message.
fn validate_statement(statement: &str) -> Result<String, String> {
    if statement.contains("\n") {
        return Err(String::from("Invalid statement"));
    }
    Ok(statement.to_string())
}

/// Validates the provided URI.
///
/// # Parameters
///
/// * `uri: &str` - The URI to validate.
///
/// # Returns
///
/// Returns a `Result<String, String>` containing the valid URI or an error message.
fn validate_uri(uri: &str) -> Result<String, String> {
    let parsed_uri = Url::parse(uri).map_err(|_| String::from("Invalid URI"))?;
    if !parsed_uri.has_host() {
        Err(String::from("Invalid URI"))
    } else {
        Ok(uri.to_string())
    }
}

fn validate_session_expires_in(expires_in: u64) -> Result<u64, String> {
    if expires_in == 0 {
        return Err(String::from("Session expires in must be greater than 0"));
    }
    Ok(expires_in)
}

fn validate_sign_in_expires_in(expires_in: u64) -> Result<u64, String> {
    if expires_in == 0 {
        return Err(String::from("Sign in expires in must be greater than 0"));
    }
    Ok(expires_in)
}
