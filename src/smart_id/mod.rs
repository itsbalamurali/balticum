mod authentication_response_validator;
mod errors;
pub mod models;
pub mod utils;
mod verification_code_calculator;

use std::{
    cmp,
    thread::sleep,
    time::Duration
};
use reqwest::{Client, Error, StatusCode};
use crate::{
    smart_id::{
        errors::SmartIdError,
        errors::SmartIdError::{DocumentUnusableException, InvalidParametersException, RequiredInteractionNotSupportedByAppException, SessionInProgress, SessionStatusMissingResult, SessionTimeoutException, SmartIdServiceUnavailable, SmartIdUnauthorized, TechnicalError, UserRefusedCertChoiceException, UserRefusedConfirmationMessageException, UserRefusedConfirmationMessageWithVcChoiceException, UserRefusedDisplayTextAndPinException, UserRefusedException, UserRefusedVcChoiceException, UserSelectedWrongVerificationCodeException},
        models::{AuthenticationHash, AuthenticationSessionRequest, AuthenticationSessionResponse, CertificateLevel, HashType, Interaction, SemanticsIdentifier, SessionEndResultCode, SessionStatus, SessionStatusCode, SessionStatusRequest, SignableData, SmartIdAuthenticationResponse, SmartIdErrorResponse}
    }
};

/// Smart-ID client for authentication and signing.
pub struct SmartIdClient {
    relying_party_uuid: String,
    relying_party_name: String,
    host_url: String,
    ssl_keys: Vec<String>,
    client: Client,
    network_interface: String,
    polling_sleep_timeout_ms: u64,
    session_status_response_socket_timeout_ms: u64,
    data_to_sign: Option<SignableData>,
    authentication_hash: Option<AuthenticationHash>,
    semantics_identifier: Option<SemanticsIdentifier>,
    document_number: Option<String>,
    certificate_level: CertificateLevel,
    allowed_interactions_order: Vec<Interaction>,
    nonce: Option<String>,
}

impl SmartIdClient {
    pub fn new(host_url: String, ssl_keys: Vec<String>, relying_party_uuid: String, relying_party_name: String) -> Self {
        SmartIdClient {
            relying_party_uuid,
            relying_party_name,
            host_url,
            ssl_keys,
            client: Client::new(),
            network_interface: String::new(),
            polling_sleep_timeout_ms: 1000,
            session_status_response_socket_timeout_ms: 1000,
            semantics_identifier: None,
            document_number: None,
            certificate_level: CertificateLevel::Qualified,
            allowed_interactions_order: Vec::new(),
            nonce: None,
            data_to_sign: None,
            authentication_hash: None,
        }
    }

    pub fn with_document_number(mut self, document_number: String) -> Self {
        self.document_number = Some(document_number);
        self
    }

    pub fn with_semantics_identifier(mut self, semantics_identifier: SemanticsIdentifier) -> Self {
        self.semantics_identifier = Some(semantics_identifier);
        self
    }

    pub fn with_semantics_identifier_as_string(
        mut self,
        semantics_identifier_as_string: String,
    ) -> Self {
        self.semantics_identifier = Some(SemanticsIdentifier::from_string(
            semantics_identifier_as_string,
        ));
        self
    }

    pub fn with_signable_data(mut self, data_to_sign: SignableData) -> Self {
        self.data_to_sign = Some(data_to_sign);
        self
    }

    pub fn with_authentication_hash(mut self, authentication_hash: AuthenticationHash) -> Self {
        self.authentication_hash = Some(authentication_hash);
        self
    }

    pub fn with_certificate_level(mut self, certificate_level: CertificateLevel) -> Self {
        self.certificate_level = certificate_level;
        self
    }

    pub fn with_allowed_interactions_order(
        mut self,
        allowed_interactions_order: Vec<Interaction>,
    ) -> Self {
        self.allowed_interactions_order = allowed_interactions_order;
        self
    }

    pub fn with_nonce(mut self, nonce: String) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn with_relying_party_uuid(mut self, relying_party_uuid: String) -> Self {
        self.relying_party_uuid = relying_party_uuid;
        self
    }

    pub fn with_relying_party_name(mut self, relying_party_name: String) -> Self {
        self.relying_party_name = relying_party_name;
        self
    }

    pub fn with_network_interface(mut self, network_interface: String) -> Self {
        self.network_interface = network_interface;
        self
    }


    async fn authenticate(
        &self,
    ) -> Result<SmartIdAuthenticationResponse, Box<dyn std::error::Error>> {
        let response = self.get_authentication_response().await.unwrap();
        let session_id = response.session_id;
        let session_status = self
            .poll_final_session_status(session_id)
            .await
            .unwrap();
        self.validate_session_status(&session_status).unwrap();
        Ok(self.create_smart_id_authentication_response(&session_status))
    }

    pub async fn start_authentication_and_return_session_id(
        &self,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = self.get_authentication_response().await.unwrap();
        Ok(response.session_id)
    }

    fn create_authentication_session_request(&self, relying_party_uuid: String, relying_party_name: String) -> AuthenticationSessionRequest {
        let mut request = AuthenticationSessionRequest::new(relying_party_uuid, relying_party_name, self.get_hash_in_base64(), self.get_hash_type());
        request.set_certificate_level(self.certificate_level.clone());
        request.set_hash_type(self.get_hash_type());
        request.set_hash(self.get_hash_in_base64().as_str());
        request.set_allowed_interactions_order((*self.allowed_interactions_order).to_vec());
        request.set_nonce(self.nonce.clone().unwrap());
        request.set_network_interface(self.network_interface.clone());
        request
    }

    fn get_hash_type(&self) -> HashType {
        if let Some(hash_type) = &self.authentication_hash {
            return hash_type.hash_type.clone();
        } else if let Some(data_to_sign) = &self.data_to_sign {
            return data_to_sign.hash_type.clone();
        }
        HashType::Sha512
    }

    fn get_hash_in_base64(&self) -> String {
        if let Some(authentication_hash) = &self.authentication_hash {
            return authentication_hash.calculate_hash_in_base64();
        } else if let Some(data_to_sign) = &self.data_to_sign {
            return data_to_sign.calculate_hash_in_base64();
        }
        String::new()
    }

    pub async fn get_authentication_request_status(&self, session_id: String) -> Result<SmartIdAuthenticationResponse, SmartIdError> {
        let session_status = self.get_session_status(session_id).await.unwrap();
        self.validate_session_status_result(session_status.to_owned()).unwrap();
        if session_status.is_running_state() {
            let mut authentication_response = SmartIdAuthenticationResponse::new();
            authentication_response.set_state(SessionStatusCode::RUNNING);
            Ok(authentication_response)
        } else {
            self.validate_session_status(&session_status).unwrap();
            Ok(self.create_smart_id_authentication_response(&session_status))
        }
    }

    async fn get_authentication_response(
        &self,
    ) -> Result<AuthenticationSessionResponse, SmartIdError> {
        self.validate_authentication_request_parameters()?;
        let request = self.create_authentication_session_request(self.relying_party_uuid.clone(), self.relying_party_name.clone());
        if let Some(document_number) = &self.document_number {
            Ok(
                self
                    .authenticate_with_document_number(document_number.to_string(), request)
                    .await
                    .unwrap())
        } else if let Some(semantics_identifier) = &self.semantics_identifier {
            Ok(self
                .authenticate_with_semantics_identifier(semantics_identifier, request)
                .await
                .unwrap())
        } else {
            Err(InvalidParametersException(
                "Either document number or semantics identifier must be set".to_string(),
            ))
        }
    }

    fn validate_authentication_request_parameters(&self) -> Result<(), SmartIdError> {
        if self.document_number.is_none() && self.semantics_identifier.is_none() {
            return Err(InvalidParametersException(
                "Either document number or semantics identifier must be set".to_string(),
            ));
        }

        self.validate_semantics_identifier_if_set().unwrap();

        if !self.is_signable_data_set() && !self.is_authentication_hash_set() {
            return Err(InvalidParametersException(
                "Signable data or hash with hash type must be set".to_string(),
            ));
        }

        self.verify_interactions_if_set().unwrap();

        Ok(())
    }

    fn is_signable_data_set(&self) -> bool {
        self.data_to_sign.is_some()
    }

    fn is_authentication_hash_set(&self) -> bool {
        self.authentication_hash.is_some()
    }


    fn create_smart_id_authentication_response(
        &self,
        session_status: &SessionStatus,
    ) -> SmartIdAuthenticationResponse {
        let session_result = session_status.get_result().unwrap();
        let session_signature = session_status.get_signature().unwrap();
        let session_certificate = session_status.get_cert().unwrap();

        let mut authentication_response = SmartIdAuthenticationResponse::new();
        authentication_response.set_end_result(session_result.get_end_result());
        authentication_response.set_ignored_properties(session_status.ignored_properties.clone());
        authentication_response.set_signed_data(self.get_data_to_sign().to_string());
        authentication_response.set_value_in_base64(session_signature.get_value().unwrap());
        authentication_response.set_algorithm_name(session_signature.get_algorithm().unwrap());
        authentication_response.set_certificate(session_certificate.get_value().unwrap());
        authentication_response.set_certificate_level(session_certificate.get_certificate_level().unwrap());
        authentication_response
            .set_interaction_flow_used(session_status.interaction_flow_used.clone());
        authentication_response.set_state(session_status.get_state());
        authentication_response.set_document_number(session_result.document_number.clone());
        authentication_response
    }

    fn get_data_to_sign(&self) -> String {
        if let Some(authentication_hash) = &self.authentication_hash {
            authentication_hash.data_to_sign.clone()
        } else if let Some(data_to_sign) = &self.data_to_sign {
            data_to_sign.data_to_sign.clone()
        } else {
            String::new()
        }
    }


    fn validate_semantics_identifier_if_set(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(semantics_identifier) = &self.semantics_identifier {
            semantics_identifier.validate()?;
        }
        Ok(())
    }

    fn verify_interactions_if_set(&self) -> Result<(), SmartIdError> {
        let interactions_order = &self.allowed_interactions_order;
        if interactions_order.is_empty() {
            return Err(InvalidParametersException(
                "Allowed interactions order must be set".to_string(),
            ));
        }
        Ok(())
    }


    pub async fn poll_final_session_status(
        &self,
        session_id: String,
    ) -> Result<SessionStatus, SmartIdError> {
        let mut session_status: Option<SessionStatus> = None;
        while session_status.is_none()
            || (session_status.is_some() && session_status.as_ref().unwrap().is_running_state())
        {
            session_status = Some(self.get_session_status(session_id.to_owned()).await.unwrap());
            if let Some(status) = &session_status {
                if !status.is_running_state() {
                    break;
                }
            }
            let microseconds = cmp::min(self.polling_sleep_timeout_ms * 1000, u64::MAX);
            sleep(Duration::from_micros(microseconds));
        }
        self.validate_session_status_result(session_status.unwrap())
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
    fn validate_session_status_result(&self, session_status: SessionStatus) -> Result<SessionStatus, SmartIdError> {
        if session_status.to_owned().is_running_state() {
            return Err(SessionInProgress);
        }

        let result = session_status.to_owned().get_result();
        if result.is_none() {
            return Err(SessionStatusMissingResult);
        }

        // let end_result = result.unwrap().get_end_result();
        if let Some(result) = session_status.to_owned().result {
            return match result.end_result {
                SessionEndResultCode::UserRefused => Err(UserRefusedException),
                SessionEndResultCode::Timeout => Err(SessionTimeoutException),
                SessionEndResultCode::DocumentUnusable => Err(DocumentUnusableException),
                SessionEndResultCode::RequiredInteractionNotSupportedByApp => {
                    Err(RequiredInteractionNotSupportedByAppException)
                }
                SessionEndResultCode::UserRefusedDisplayTextAndPIN => {
                    Err(UserRefusedDisplayTextAndPinException)
                }
                SessionEndResultCode::UserRefusedVCChoice => {
                    Err(UserRefusedVcChoiceException)
                }
                SessionEndResultCode::UserRefusedConfirmationMessage => {
                    Err(UserRefusedConfirmationMessageException)
                }
                SessionEndResultCode::UserRefusedConfirmationMessageWithVCChoice => {
                    Err(UserRefusedConfirmationMessageWithVcChoiceException)
                }
                SessionEndResultCode::UserRefusedCertChoice => {
                    Err(UserRefusedCertChoiceException)
                }
                SessionEndResultCode::WrongVC => {
                    Err(UserSelectedWrongVerificationCodeException)
                }
                SessionEndResultCode::Ok => Ok(session_status.to_owned()),
                _ => Err(TechnicalError(
                    "Session status end result is unknown".to_string(),
                )),
            };
        } else {
            return Err(TechnicalError(
                "Result is missing in the session status response".to_string(),
            ));
        }
    }

    pub async fn authenticate_with_document_number(
        &self,
        document_number: String,
        request: AuthenticationSessionRequest,
    ) -> Result<AuthenticationSessionResponse, SmartIdError> {
        let url = format!(
            "{}/authentication/document/{}",
            self.host_url.trim_end_matches("/"), document_number
        );
        self.post_authentication_request(&url, request).await
    }

    pub async fn authenticate_with_semantics_identifier(
        &self,
        semantics_identifier: &SemanticsIdentifier,
        request: AuthenticationSessionRequest,
    ) -> Result<AuthenticationSessionResponse, SmartIdError> {
        let url = format!(
            "{}/authentication/etsi/{}",
            self.host_url.trim_end_matches("/"),
            semantics_identifier.as_string()
        );
        self.post_authentication_request(&url, request).await
    }

    pub async fn get_session_status(&self, session_id: String) -> Result<SessionStatus, SmartIdError> {
        let mut request = SessionStatusRequest::new(session_id);
        let timeout = self.session_status_response_socket_timeout_ms;
        request.set_session_status_response_socket_timeout_ms(timeout);
        if !self.network_interface.is_empty() {
            request.set_network_interface(self.network_interface.clone());
        }
        let session_status = self.get_session_status_request(request).await.unwrap();
        self.validate_session_status_result(session_status.to_owned()).unwrap();
        Ok(session_status)
    }

    /// Gets the session status with the given request.
    async fn get_session_status_request(
        &self,
        request: SessionStatusRequest,
    ) -> Result<SessionStatus, Error> {
        let url = format!("{}/session/{}", self.host_url.trim_end_matches("/"), request.session_id);
        let response = self
            .client
            .get(url)
            .send()
            .await?
            .json::<SessionStatus>()
            .await?;
        Ok(response)
    }

    /// Initiates a new authentication session with the given request.
    async fn post_authentication_request(
        &self,
        url: &str,
        request: AuthenticationSessionRequest,
    ) -> Result<AuthenticationSessionResponse, SmartIdError> {
        println!("Request URL: {}",url);
        println!("Request Payload: {}",serde_json::to_string(&request).unwrap());
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await.unwrap();
        let http_status_code = response.status();
        return match http_status_code {
            StatusCode::OK => Ok(response.json::<AuthenticationSessionResponse>().await.unwrap()),
            StatusCode::BAD_REQUEST | StatusCode::METHOD_NOT_ALLOWED => Err(TechnicalError(response.json::<SmartIdErrorResponse>().await.unwrap().message)),
            StatusCode::UNAUTHORIZED => Err(SmartIdUnauthorized),
            StatusCode::SERVICE_UNAVAILABLE => Err(SmartIdServiceUnavailable),
            _ => {
                Err(TechnicalError(format!("Response was '{}', status code was {}", response.text().await.unwrap(), http_status_code)))
            }
        }

    }
}
