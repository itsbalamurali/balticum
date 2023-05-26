use std::thread::sleep;
use std::time::Duration;
use std::cmp;
use crate::smart_id::exceptions::Exception;
use crate::smart_id::exceptions::Exception::{DocumentUnusableException, RequiredInteractionNotSupportedByAppException, SessionTimeoutException, TechnicalErrorException, UserRefusedCertChoiceException, UserRefusedConfirmationMessageException, UserRefusedConfirmationMessageWithVcChoiceException, UserRefusedDisplayTextAndPinException, UserRefusedException, UserRefusedVcChoiceException, UserSelectedWrongVerificationCodeException};
use crate::smart_id::models::{SessionEndResultCode, SessionStatus};
use crate::smart_id::session_status_fetcher::{SessionStatusFetcher, SessionStatusFetcherBuilder};
use crate::smart_id::smart_id_rest_connector::SmartIdRestConnector;

pub struct SessionStatusPoller<'a> {
    connector: &'a SmartIdRestConnector<'a>,
    polling_sleep_timeout_ms: u64,
    session_status_response_socket_timeout_ms: u64,
    network_interface: Option<String>,
}

impl SessionStatusPoller<'_> {
    pub fn new(connector: &SmartIdRestConnector) -> Self {
        SessionStatusPoller {
            connector,
            polling_sleep_timeout_ms: 1000,
            session_status_response_socket_timeout_ms: 0,
            network_interface: None,
        }
    }

    pub async fn fetch_final_session_status(&self, session_id: String) -> Result<Option<SessionStatus>, Box<dyn std::error::Error>> {
        let session_status = self.poll_for_final_session_status(session_id).await.unwrap();
        self.validate_result(&session_status).unwrap();
        Ok(session_status)
    }

    async fn poll_for_final_session_status(&self, session_id: String) -> Result<Option<SessionStatus>, Box<dyn std::error::Error>> {
        let mut session_status: Option<SessionStatus> = None;
        let session_status_fetcher = self.create_session_status_fetcher(session_id)?;

        while session_status.is_none() || (session_status.is_some() && session_status.as_ref().unwrap().is_running_state()) {
            session_status = Some(session_status_fetcher.get_session_status().await);
            if let Some(status) = &session_status {
                if !status.is_running_state() {
                    break;
                }
            }
            let microseconds = self.convert_ms_to_micros(self.polling_sleep_timeout_ms);
            sleep(Duration::from_micros(microseconds));
        }

        Ok(session_status)
    }

    fn validate_result(&self, session_status: &Option<SessionStatus>) -> Result<(), Exception> {
        if let Some(status) = session_status {
            if let Some(result) = &status.result {
                match result.end_result {
                    SessionEndResultCode::USER_REFUSED => Err(UserRefusedException),
                    SessionEndResultCode::TIMEOUT => Err(SessionTimeoutException),
                    SessionEndResultCode::DOCUMENT_UNUSABLE => Err(DocumentUnusableException),
                    SessionEndResultCode::REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP => Err(RequiredInteractionNotSupportedByAppException),
                    SessionEndResultCode::USER_REFUSED_DISPLAYTEXTANDPIN => Err(UserRefusedDisplayTextAndPinException),
                    SessionEndResultCode::USER_REFUSED_VC_CHOICE => Err(UserRefusedVcChoiceException),
                    SessionEndResultCode::USER_REFUSED_CONFIRMATIONMESSAGE => Err(UserRefusedConfirmationMessageException),
                    SessionEndResultCode::USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE => Err(UserRefusedConfirmationMessageWithVcChoiceException),
                    SessionEndResultCode::USER_REFUSED_CERT_CHOICE => Err(UserRefusedCertChoiceException),
                    SessionEndResultCode::WRONG_VC => Err(UserSelectedWrongVerificationCodeException),
                    SessionEndResultCode::OK => Ok(()),
                    _ => Err(TechnicalErrorException("Session status end result is unknown".to_string())),
                }
            } else {
                Err(TechnicalErrorException("Result is missing in the session status response".to_string()))
            }
        } else {
            Err(TechnicalErrorException("Session status is missing".to_string()))
        }
    }

    pub fn set_polling_sleep_timeout_ms(&mut self, timeout: u64) -> &mut Self {
        self.polling_sleep_timeout_ms = timeout;
        self
    }

    fn convert_ms_to_micros(&self, milliseconds: u64) -> u64 {
        cmp::min(milliseconds * 1000, u64::MAX)
    }

    pub fn set_session_status_response_socket_timeout_ms(&mut self, timeout: u64) -> &mut Self {
        self.session_status_response_socket_timeout_ms = timeout;
        self
    }

    fn create_session_status_fetcher(&self, session_id: String) -> Result<SessionStatusFetcher, Box<dyn std::error::Error>> {
        let mut builder: SessionStatusFetcherBuilder = SessionStatusFetcherBuilder::new(self.connector.clone());
        builder = builder.with_session_id(session_id);
        builder = builder.with_session_status_response_socket_timeout_ms(self.session_status_response_socket_timeout_ms).unwrap();
        builder = if let Some(network_interface) = &self.network_interface {
            builder.with_network_interface(network_interface.clone())
        } else {
            builder
        };
        Ok(builder.build())
    }

    pub fn with_network_interface(&mut self, network_interface: String) -> &mut Self {
        self.network_interface = Some(network_interface);
        self
    }
}
