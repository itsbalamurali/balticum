use crate::smart_id::exceptions::Exception;
use crate::smart_id::exceptions::Exception::{
    DocumentUnusableException, RequiredInteractionNotSupportedByAppException,
    SessionTimeoutException, TechnicalErrorException, UserRefusedCertChoiceException,
    UserRefusedConfirmationMessageException, UserRefusedConfirmationMessageWithVcChoiceException,
    UserRefusedDisplayTextAndPinException, UserRefusedException, UserRefusedVcChoiceException,
};
use crate::smart_id::models::{
    AuthenticationHash, SessionEndResultCode, SessionStatus, SessionStatusCode,
    SessionStatusRequest, SignableData, SmartIdAuthenticationResponse,
};
use crate::smart_id::smart_id_rest_connector::SmartIdRestConnector;

pub struct SessionStatusFetcher<'a> {
    pub session_id: String,
    connector: SmartIdRestConnector<'a>,
    pub data_to_sign: Option<&'a SignableData>,
    pub authentication_hash: Option<&'a AuthenticationHash>,
    pub session_status_response_socket_timeout_ms: u64,
    pub network_interface: Option<String>,
}

impl<'a> SessionStatusFetcher<'a> {
    pub fn new(endpoint_url: String,session_id: String) -> SessionStatusFetcher<'a> {
        let connector = SmartIdRestConnector::new(endpoint_url);
        SessionStatusFetcher {
            session_id: session_id,
            connector,
            data_to_sign: None,
            authentication_hash: None,
            session_status_response_socket_timeout_ms: 1000,
            network_interface: None,
        }
    }

    pub fn set_session_id(mut self, session_id: String) -> Self {
        self.session_id = session_id;
        self
    }

    pub fn get_session_id(&self) -> String {
        self.session_id.clone()
    }

    pub fn get_data_to_sign(&self) -> &str {
        if let Some(authentication_hash) = &self.authentication_hash {
            authentication_hash.get_data_to_sign()
        } else if let Some(data_to_sign) = &self.data_to_sign {
            data_to_sign.get_data_to_sign()
        } else {
            ""
        }
    }

    pub fn set_session_status_response_socket_timeout_ms(
        mut self,
        session_status_response_socket_timeout_ms: u64,
    ) -> Self {
        self.session_status_response_socket_timeout_ms = session_status_response_socket_timeout_ms;
        self
    }

    pub fn set_network_interface(mut self, network_interface: Option<String>) -> Self {
        self.network_interface = network_interface;
        self
    }

    pub async fn get_authentication_response(&self) -> SmartIdAuthenticationResponse {
        let session_status = self.fetch_session_status().await;
        if session_status.is_running_state() {
            let mut authentication_response = SmartIdAuthenticationResponse::new();
            authentication_response.set_state(SessionStatusCode::RUNNING);
            authentication_response
        } else {
            self.validate_session_status(&session_status);
            self.create_smart_id_authentication_response(&session_status)
        }
    }

    pub async fn get_session_status(&self) -> SessionStatus {
        let request = self.create_session_status_request(self.session_id.clone());
        self.connector.get_session_status(request).await.unwrap()
    }

    async fn fetch_session_status(&self) -> SessionStatus {
        let session_status = self.get_session_status().await;
        self.validate_result(&session_status);
        session_status
    }

    fn create_session_status_request(&self, session_id: String) -> SessionStatusRequest {
        let mut request = SessionStatusRequest::new(session_id);
        let timeout = self.session_status_response_socket_timeout_ms;
        request.set_session_status_response_socket_timeout_ms(timeout);
        if let Some(interface) = &self.network_interface {
            request.set_network_interface(interface.clone());
        }
        request
    }

    fn validate_session_status(&self, session_status: &SessionStatus) {
        if session_status.get_signature().is_none() {
            panic!("Signature was not present in the response");
        }
        if session_status.get_cert().is_none() {
            panic!("Certificate was not present in the response");
        }
    }

    fn validate_result(&self, session_status: &SessionStatus) {
        if session_status.is_running_state() {
            return;
        }

        let result = session_status.get_result();
        if result.is_none() {
            panic!("Result is missing in the session status response");
        }

        let end_result = result.unwrap().get_end_result();
        match end_result {
            SessionEndResultCode::USER_REFUSED => {
                panic!("{}", UserRefusedException);
            }
            SessionEndResultCode::TIMEOUT => {
                panic!("{}", SessionTimeoutException);
            }
            SessionEndResultCode::DOCUMENT_UNUSABLE => {
                panic!("{}", DocumentUnusableException);
            }
            SessionEndResultCode::REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP => {
                panic!("{}", RequiredInteractionNotSupportedByAppException);
            }
            SessionEndResultCode::USER_REFUSED_DISPLAYTEXTANDPIN => {
                panic!("{}", UserRefusedDisplayTextAndPinException);
            }
            SessionEndResultCode::USER_REFUSED_VC_CHOICE => {
                panic!("{}", UserRefusedVcChoiceException);
            }
            SessionEndResultCode::USER_REFUSED_CONFIRMATIONMESSAGE => {
                panic!("{}", UserRefusedConfirmationMessageException);
            }
            SessionEndResultCode::USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE => {
                panic!("{}", UserRefusedConfirmationMessageWithVcChoiceException);
            }
            SessionEndResultCode::USER_REFUSED_CERT_CHOICE => {
                panic!("{}", UserRefusedCertChoiceException);
            }
            SessionEndResultCode::OK => {}
            _ => panic!("Session status end result is '{}'", end_result),
        }
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
        authentication_response.set_signed_data(self.get_data_to_sign().to_string());
        authentication_response.set_value_in_base64(session_signature.get_value().unwrap());
        authentication_response.set_algorithm_name(session_signature.get_algorithm().unwrap());
        authentication_response.set_certificate(session_certificate.get_value().unwrap());
        authentication_response.set_certificate_level(session_certificate.get_certificate_level().unwrap());
        authentication_response.set_state(session_status.get_state());
        authentication_response
    }
}

pub struct SessionStatusFetcherBuilder<'a> {
    session_id: Option<String>,
    connector: SmartIdRestConnector<'a>,
    data_to_sign: Option<SignableData>,
    authentication_hash: Option<AuthenticationHash>,
    session_status_response_socket_timeout_ms: u64,
    network_interface: Option<String>,
}

impl<'a> SessionStatusFetcherBuilder<'a> {
    pub fn new(endpoint_url: String) -> SessionStatusFetcherBuilder<'a> {
        let connector = SmartIdRestConnector::new(endpoint_url);
        SessionStatusFetcherBuilder {
            session_id: None,
            connector,
            data_to_sign: None,
            authentication_hash: None,
            session_status_response_socket_timeout_ms: 1000,
            network_interface: None,
        }
    }


    pub fn with_session_status_response_socket_timeout_ms(
        mut self,
        session_status_response_socket_timeout_ms: u64,
    ) -> Result<Self, Exception> {
        self.session_status_response_socket_timeout_ms = session_status_response_socket_timeout_ms;
        Ok(self)
    }

    pub fn with_network_interface(mut self, network_interface: &String) -> Self {
        self.network_interface = Some(network_interface.clone());
        self
    }

    // pub async fn get_authentication_response(&self) -> SmartIdAuthenticationResponse {
    //     self.build().get_authentication_response().await.clone()
    // }

}
