mod errors;
pub mod models;
pub mod utils;
mod verification_code_calculator;

use crate::smart_id::{
    errors::SmartIdError,
    errors::SmartIdError::{
        DocumentUnusableException, InvalidParametersException,
        RequiredInteractionNotSupportedByAppException, SessionInProgress,
        SessionStatusMissingResult, SessionTimeoutException, SmartIdServiceUnavailable,
        SmartIdUnauthorized, TechnicalError, UserRefusedCertChoiceException,
        UserRefusedConfirmationMessageException,
        UserRefusedConfirmationMessageWithVcChoiceException, UserRefusedDisplayTextAndPinException,
        UserRefusedException, UserRefusedVcChoiceException,
        UserSelectedWrongVerificationCodeException,
    },
    models::{
        AuthenticationHash, AuthenticationSessionRequest, AuthenticationSessionResponse,
        CertificateLevel, Interaction, SemanticsIdentifier, SessionEndResultCode,
        SessionStatus, SmartIdErrorResponse, // Removed SessionStatusRequest
    },
};
use reqwest::{Certificate, Client, StatusCode}; // Removed Error
use std::{cmp, thread::sleep, time::Duration};

/// Smart-ID client for authentication and signing.
#[allow(dead_code)] // To suppress warnings for unused fields if not all are used yet
pub struct SmartIdClient<'a> {
    relying_party_uuid: String,
    relying_party_name: String,
    host_url: String,
    ssl_pinned_public_keys: Option<&'a Certificate>,
    network_interface: String,
    polling_sleep_timeout_ms: u64,
    session_status_response_socket_timeout_ms: u64,
    authentication_hash: AuthenticationHash,
    document_number: Option<String>, // Marked with allow(dead_code) implicitly by struct attribute
    certificate_level: CertificateLevel, // Marked with allow(dead_code) implicitly by struct attribute
    allowed_interactions_order: Vec<Interaction>, // Marked with allow(dead_code) implicitly by struct attribute
    nonce: Option<String>, // Marked with allow(dead_code) implicitly by struct attribute
}

impl<'a>  SmartIdClient<'a>  {
    /// Create a new Smart-ID client.
    pub fn new(
        host_url: String,
        relying_party_uuid: String,
        relying_party_name: String,
        authentication_hash: AuthenticationHash,
        ssl_pinned_public_keys: Option<&'a Certificate>,
    ) -> Self {
        SmartIdClient {
            relying_party_uuid,
            relying_party_name,
            host_url,
            ssl_pinned_public_keys,
            network_interface: String::new(),
            polling_sleep_timeout_ms: 1000,
            session_status_response_socket_timeout_ms: 1000,
            document_number: None,
            certificate_level: CertificateLevel::Qualified,
            allowed_interactions_order: Vec::new(),
            nonce: None,
            authentication_hash,
        }
    }

    /// Builds HTTP client with or without SSL pinning
    fn build_http_client(&self) -> Client {
        let http_client = Client::builder();
        if self.ssl_pinned_public_keys.is_some() {
            return http_client
                .add_root_certificate(self.ssl_pinned_public_keys.clone().unwrap().clone())
                .build()
                .unwrap();
        }
        return http_client.build().unwrap();
    }

    fn create_auth_session_request(
        &self,
        auth_hash: AuthenticationHash,
        nonce: Option<String>,
        certificate_level: CertificateLevel,
        allowed_interactions_order: Vec<Interaction>,
        network_interface: Option<String>,
    ) -> AuthenticationSessionRequest {
        AuthenticationSessionRequest {
            relying_party_uuid: self.relying_party_uuid.clone(),
            relying_party_name: self.relying_party_name.clone(),
            hash_type: auth_hash.get_hash_type(),
            hash: auth_hash.get_hash(),
            nonce,
            certificate_level,
            network_interface,
            allowed_interactions_order,
        }
    }

    pub async fn get_authentication_request_status(
        &self,
        session_id: String,
    ) -> Result<SessionStatus, SmartIdError> {
        let session_status = self.get_session_status(session_id).await.unwrap();
        self.validate_session_status_result(session_status.to_owned())
            .unwrap();
        if session_status.is_running_state() {
            Ok(session_status)
        } else {
            self.validate_session_status(&session_status).unwrap();
            Ok(session_status)
        }
    }

    #[allow(dead_code)] // Method is unused
    fn validate_auth_request_parameters(&self) -> Result<(), SmartIdError> {
        if self.document_number.is_none() {
            return Err(InvalidParametersException(
                "Either document number or semantics identifier must be set".to_string(),
            ));
        }

        self.verify_interactions_if_set().unwrap();

        Ok(())
    }

    #[allow(dead_code)] // Method is unused
    fn verify_interactions_if_set(&self) -> Result<(), SmartIdError> {
        let interactions_order = &self.allowed_interactions_order;
        if interactions_order.is_empty() {
            return Err(InvalidParametersException(
                "Allowed interactions order must be set".to_string(),
            ));
        }
        Ok(())
    }

    /// Polls session status until it is not in running state.
    pub async fn poll_final_session_status(
        &self,
        session_id: String,
    ) -> Result<SessionStatus, SmartIdError> {
        let mut session_status_option: Option<SessionStatus> = None; // Renamed to avoid conflict
        // Loop while session_status_option is None or the session is in a running state
        while session_status_option.is_none() ||
              (session_status_option.as_ref().map_or(false, |s| s.is_running_state())) {

            let current_status = self.get_session_status(session_id.to_owned()).await?; // Use ? for error propagation

            if !current_status.is_running_state() {
                session_status_option = Some(current_status);
                break;
            }
            session_status_option = Some(current_status); // Store current status even if running, for next loop check

            let microseconds = cmp::min(self.polling_sleep_timeout_ms * 1000, u64::MAX);
            sleep(Duration::from_micros(microseconds));
        }
        // Unwrap is safe here because the loop condition ensures it's Some if we break
        self.validate_session_status_result(session_status_option.unwrap())
    }

    /// Validates session status and returns it if it is valid
    fn validate_session_status(&self, session_status: &SessionStatus) -> Result<(), SmartIdError> {
        if session_status.signature.is_none() {
            return Err(TechnicalError(
                "Signature was not present in the response".to_string(),
            ));
        }
        if session_status.cert.is_none() {
            return Err(TechnicalError(
                "Certificate was not present in the response".to_string(),
            ));
        }
        Ok(())
    }

    /// Validates session status result and returns it if it is valid
    fn validate_session_status_result(
        &self,
        session_status: SessionStatus,
    ) -> Result<SessionStatus, SmartIdError> {
        if session_status.is_running_state() {
            return Err(SessionInProgress);
        }

        let result_opt = session_status.get_result(); // Use getter if available, else direct access
        if result_opt.is_none() {
            return Err(SessionStatusMissingResult);
        }

        let result_data = result_opt.unwrap(); // Known to be Some now

        match result_data.end_result {
            SessionEndResultCode::UserRefused => Err(UserRefusedException),
            SessionEndResultCode::Timeout => Err(SessionTimeoutException),
            SessionEndResultCode::DocumentUnusable => Err(DocumentUnusableException),
            SessionEndResultCode::RequiredInteractionNotSupportedByApp => {
                Err(RequiredInteractionNotSupportedByAppException)
            }
            SessionEndResultCode::UserRefusedDisplayTextAndPIN => {
                Err(UserRefusedDisplayTextAndPinException)
            }
            SessionEndResultCode::UserRefusedVCChoice => Err(UserRefusedVcChoiceException),
            SessionEndResultCode::UserRefusedConfirmationMessage => {
                Err(UserRefusedConfirmationMessageException)
            }
            SessionEndResultCode::UserRefusedConfirmationMessageWithVCChoice => {
                Err(UserRefusedConfirmationMessageWithVcChoiceException)
            }
            SessionEndResultCode::UserRefusedCertChoice => Err(UserRefusedCertChoiceException),
            SessionEndResultCode::WrongVC => Err(UserSelectedWrongVerificationCodeException),
            SessionEndResultCode::Ok => Ok(session_status),
        }
    }

    /// Authenticate with document number.
    pub async fn authenticate_with_document_number(
        &self,
        document_number: String,
        nonce: Option<String>,
        certificate_level: CertificateLevel,
        allowed_interactions_order: Vec<Interaction>,
        network_interface: Option<String>,
    ) -> Result<AuthenticationSessionResponse, SmartIdError> {
        let request = self.create_auth_session_request(
            self.authentication_hash.clone(), // Use client's main auth hash
            nonce,
            certificate_level,
            allowed_interactions_order,
            network_interface,
        );
        let url = format!(
            "{}/authentication/document/{}",
            self.host_url.trim_end_matches("/"),
            document_number
        );
        self.post_authentication_request(&url, request).await
    }

    /// Authenticate with a semantics identifier.
    pub async fn authenticate_with_semantics_identifier(
        &self,
        semantics_identifier: &SemanticsIdentifier,
        auth_hash: AuthenticationHash, // Allow passing a specific hash for this auth method
        nonce: Option<String>,
        certificate_level: CertificateLevel,
        allowed_interactions_order: Vec<Interaction>,
        network_interface: Option<String>,
    ) -> Result<AuthenticationSessionResponse, SmartIdError> {
        let request = self.create_auth_session_request(
            auth_hash, // Use the provided auth_hash
            nonce,
            certificate_level,
            allowed_interactions_order,
            network_interface,
        );
        let url = format!(
            "{}/authentication/etsi/{}",
            self.host_url.trim_end_matches("/"),
            semantics_identifier.as_string()
        );
        self.post_authentication_request(&url, request).await
    }

    pub async fn get_session_status(
        &self,
        session_id: String,
    ) -> Result<SessionStatus, SmartIdError> {
        let mut request_params = Vec::new(); // Use Vec for query params
        let timeout_str = self.session_status_response_socket_timeout_ms.to_string();
        request_params.push(("timeoutMs", timeout_str.as_str()));

        // Add network_interface if it's not empty
        // Note: The original Java client has a SessionStatusRequest object.
        // Here, we are building the URL directly.
        // The Java client adds networkInterface to the SessionStatusRequest if it's set for the client.
        // However, the API spec for GET /session/{sessionId} usually takes query parameters.
        // Let's assume timeoutMs is the primary one. If networkInterface is also a query param for GET,
        // it should be added here. The provided code doesn't show it being added to GET.
        // For now, only timeoutMs is added as a query param as per typical session status polling.

        let mut url_string = format!(
            "{}/session/{}",
            self.host_url.trim_end_matches("/"),
            session_id
        );

        if !request_params.is_empty() {
            url_string.push('?');
            url_string.push_str(
                &request_params
                    .into_iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<String>>()
                    .join("&")
            );
        }

        println!("Request URL: {}", url_string);
        let response = self
            .build_http_client()
            .get(&url_string) // Pass as &str
            .send()
            .await
            .map_err(|e| TechnicalError(format!("Failed to send session status request: {}", e)))?;

        let http_status_code = response.status();
        let resp_text = response.text().await.map_err(|e| TechnicalError(format!("Failed to get session status response text: {}", e)))?;
        println!("Response: {}", resp_text);

        match http_status_code {
            StatusCode::OK => {
                let session_status: SessionStatus = serde_json::from_str(&resp_text)
                    .map_err(|e| TechnicalError(format!("Failed to parse session status response: {}", e)))?;
                // `validate_session_status_result` itself returns Result<SessionStatus, SmartIdError>
                // so we return its result directly.
                self.validate_session_status_result(session_status)
            }
            StatusCode::UNAUTHORIZED => Err(SmartIdUnauthorized),
            StatusCode::SERVICE_UNAVAILABLE => Err(SmartIdServiceUnavailable),
            _ => Err(TechnicalError(format!(
                "Session status request failed with status {}: {}",
                http_status_code, resp_text
            ))),
        }
    }


    /// Initiates a new authentication session with the given request.
    async fn post_authentication_request(
        &self,
        url: &str,
        request: AuthenticationSessionRequest,
    ) -> Result<AuthenticationSessionResponse, SmartIdError> {
        println!("Request URL: {}", url);
        println!(
            "Request Payload: {}",
            serde_json::to_string(&request).unwrap()
        );
        let response = self.build_http_client().post(url).json(&request).send().await
            .map_err(|e| TechnicalError(format!("Authentication POST request failed: {}", e)))?;

        let http_status_code = response.status();
        let resp_text = response.text().await.map_err(|e| TechnicalError(format!("Failed to read authentication response text: {}", e)))?;
        println!("Response: {}", resp_text);

        match http_status_code {
            StatusCode::OK => {
                serde_json::from_str::<AuthenticationSessionResponse>(&resp_text)
                    .map_err(|e| TechnicalError(format!("Failed to parse authentication response: {}", e)))
            }
            StatusCode::BAD_REQUEST | StatusCode::METHOD_NOT_ALLOWED => {
                // Try to parse as SmartIdErrorResponse, then fall back
                let err_details = serde_json::from_str::<SmartIdErrorResponse>(&resp_text)
                    .map(|e| e.message)
                    .unwrap_or_else(|_| resp_text.clone());
                Err(TechnicalError(err_details))
            }
            StatusCode::UNAUTHORIZED => Err(SmartIdUnauthorized),
            StatusCode::SERVICE_UNAVAILABLE => Err(SmartIdServiceUnavailable),
            _ => Err(TechnicalError(format!(
                "Response was '{}', status code was {}",
                resp_text, http_status_code
            ))),
        }
    }
}

#[cfg(test)]
mod tests;
