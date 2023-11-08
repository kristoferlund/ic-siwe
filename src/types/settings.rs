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
    pub expires_in: u32,
}

pub fn get_settings() -> Result<Settings, String> {
    SETTINGS.with(|settings| {
        settings
            .borrow()
            .as_ref()
            .cloned() // Clone the Settings value
            .ok_or_else(|| String::from("Settings are not initialized"))
    })
}

pub struct SettingsBuilder {
    settings: Settings,
}

impl SettingsBuilder {
    pub fn new(domain: String, uri: String) -> Self {
        SettingsBuilder {
            settings: Settings {
                domain,
                uri,
                chain_id: 1, // defaults to Ethereum mainnet
                scheme: String::from("https"),
                statement: String::from("SIWE Fields:"),
                expires_in: 60 * 60 * 24, // 24 hours
            },
        }
    }

    pub fn chain_id(mut self, chain_id: u32) -> Self {
        self.settings.chain_id = chain_id;
        self
    }

    pub fn scheme(mut self, scheme: String) -> Self {
        self.settings.scheme = scheme;
        self
    }

    pub fn statement(mut self, statement: String) -> Self {
        self.settings.statement = statement;
        self
    }

    pub fn expires_in(mut self, expires_in: u32) -> Self {
        self.settings.expires_in = expires_in;
        self
    }

    pub fn build(self) -> Result<Settings, String> {
        validate_domain(&self.settings.scheme, &self.settings.domain)?;
        validate_scheme(&self.settings.scheme)?;
        validate_statement(&self.settings.statement)?;
        validate_uri(&self.settings.uri)?;

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
