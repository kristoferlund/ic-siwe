extern crate serde;
extern crate serde_json;

/// Represents the settings for initializing SIWE.
///
/// This struct is used to pass settings to the `init` function for SIWE configuration.
#[derive(Default, Debug, Clone)]
pub struct SiweSettings {
    pub domain: String,
    pub scheme: String,
    pub statement: String,
    pub uri: String,
    pub chain_id: u32,
    pub expires_in: u32,
}
pub struct SiweSettingsBuilder {
    settings: SiweSettings,
}

impl SiweSettingsBuilder {
    pub fn new(domain: String, uri: String) -> Self {
        SiweSettingsBuilder {
            settings: SiweSettings {
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

    pub fn build(self) -> SiweSettings {
        self.settings
    }
}
