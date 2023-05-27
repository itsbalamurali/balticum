use crate::smart_id::authentication::AuthenticationApi;
use std::collections::HashMap;

pub struct SmartIdApi {
    pub client: SmartIdClient,
    pub base_url: String,
}

impl SmartIdApi {
    pub fn new(client: SmartIdClient) -> Self {
        let base_url = "https://smart-id.com/api/v2/";
        SmartIdApi {
            client,
            base_url: base_url.to_string(),
        }
    }
}

pub trait AbstractApi {}

pub struct SmartIdClient {
    apis: HashMap<String, Box<dyn AbstractApi>>,
    relying_party_uuid: String,
    relying_party_name: String,
    host_url: String,
    ssl_keys: Vec<String>,
}

impl SmartIdClient {
    const VERSION: &'static str = "2.3.1";

    pub fn new() -> Self {
        SmartIdClient {
            apis: HashMap::new(),
            relying_party_uuid: String::new(),
            relying_party_name: String::new(),
            host_url: String::new(),
            ssl_keys: Vec::new(),
        }
    }

    pub fn authentication(&mut self) -> AuthenticationApi {
            AuthenticationApi::new(self)
    }

    pub fn set_relying_party_uuid(&mut self, relying_party_uuid: String) -> &mut Self {
        self.relying_party_uuid = relying_party_uuid;
        self
    }

    pub fn get_relying_party_uuid(&self) -> String {
        self.relying_party_uuid.to_string()
    }

    pub fn set_relying_party_name(&mut self, relying_party_name: String) -> &mut Self {
        self.relying_party_name = relying_party_name;
        self
    }

    pub fn get_relying_party_name(&self) -> String {
        self.relying_party_name.clone()
    }

    pub fn set_host_url(&mut self, host_url: String) -> &mut Self {
        self.host_url = host_url;
        self
    }

    pub fn get_host_url(&self) -> String {
        self.host_url.clone()
    }

    pub fn set_public_ssl_keys(&mut self, ssl_keys: Vec<String>) -> &mut Self {
        self.ssl_keys = ssl_keys;
        self
    }

    pub fn get_public_ssl_keys(&self) -> Vec<String> {
        self.ssl_keys.clone()
    }
}
