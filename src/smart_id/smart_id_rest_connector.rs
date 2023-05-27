use crate::smart_id::models::{
    AuthenticationSessionRequest, AuthenticationSessionResponse, SemanticsIdentifier,
    SessionStatus, SessionStatusRequest,
};
use reqwest::{Client, Error};

#[derive(Clone)]
pub struct SmartIdRestConnector<'a> {
    endpoint_url: String,
    relying_party_uuid: Option<&'a str>,
    relying_party_name: Option<&'a str>,
    client: Client,
}

impl SmartIdRestConnector<'_> {
    pub fn new(endpoint_url: String) -> Self {
        SmartIdRestConnector {
            endpoint_url,
            client: Client::new(),
            relying_party_uuid: None,
            relying_party_name: None,
        }
    }

    pub async fn authenticate(
        &self,
        document_number: String,
        request: AuthenticationSessionRequest,
    ) -> Result<AuthenticationSessionResponse, Error> {
        let url = format!(
            "{}/authentication/document/{}",
            self.endpoint_url, document_number
        );
        self.post_authentication_request(&url, request).await
    }

    pub async fn authenticate_with_semantics_identifier(
        &self,
        semantics_identifier: &SemanticsIdentifier,
        request: AuthenticationSessionRequest,
    ) -> Result<AuthenticationSessionResponse, Error> {
        let url = format!(
            "{}/authentication/etsi/{}",
            self.endpoint_url,
            semantics_identifier.as_string()
        );
        self.post_authentication_request(&url, request).await
    }

    pub async fn get_session_status(
        &self,
        request: SessionStatusRequest,
    ) -> Result<SessionStatus, Error> {
        let url = format!("{}/session/{}", self.endpoint_url, request.session_id);
        let response = self
            .client
            .get(url)
            .send()
            .await?
            .json::<SessionStatus>()
            .await?;
        Ok(response)
    }

    pub async fn post_authentication_request(
        &self,
        url: &str,
        request: AuthenticationSessionRequest,
    ) -> Result<AuthenticationSessionResponse, Error> {
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await?
            .json::<AuthenticationSessionResponse>()
            .await?;
        Ok(response)
    }

    pub fn set_public_ssl_keys(&mut self, public_ssl_keys: Vec<String>) {
        //TODO: implement setting public ssl keys
        // self.client = self.client.dangerous_add_root_certificate(
        //     reqwest::Certificate::from_pem(
        //         public_ssl_keys.join("\n").as_bytes()
        //     ).unwrap()
        // );
    }

    pub fn get_relying_party_uuid(&self) -> Option<&str> {
        self.relying_party_uuid

    }

    pub fn get_relying_party_name(&self) -> Option<&str> {
        self.relying_party_name
    }

    pub fn with_relying_party_uuid(&mut self, relying_party_uuid: &str) -> &mut Self {
        //TODO: implement setting relying party uuid
        // self.client = self.client
        //     .builder()
        //     .default_headers(
        //         std::iter::once(("relyingPartyUUID", relying_party_uuid.to_owned()))
        //             .collect()
        //     )
        //     .build()
        //     .unwrap();
        self
    }

    pub fn with_relying_party_name(&mut self, relying_party_name: &str) -> &mut Self {
        //TODO: implement setting relying party name
        // self.client = self.client
        //     .builder()
        //     .default_headers(
        //         std::iter::once(("relyingPartyName", relying_party_name.to_owned()))
        //             .collect()
        //     )
        //     .build()
        //     .unwrap();
        self
    }

}
