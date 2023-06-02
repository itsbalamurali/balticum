mod errors;
mod models;

use std::thread;
use std::time::Duration;

use reqwest::header::HeaderMap;
use reqwest::{Certificate, Client};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::mobile_id::errors::MobileIdError;
use crate::mobile_id::errors::MobileIdError::{
    MidClientOld, MidForbidden, MidInternalError, MidLimitExceeded, MidNoSuitableAccountFound,
    MidNotMidClient, MidPersonShouldViewAppOrSelfServicePortalNow, MidPhoneAbsent,
    MidServiceUnavailable, MidSessionTimeout, MidSignatureHashMismatch, MidSimError,
    MidSystemUnderMaintenance, MidUnauthorized, MidUserCancelled,
};
use crate::mobile_id::models::SessionStatusState::RUNNING;
use crate::mobile_id::models::{
    AuthenticationRequest, AuthenticationResponse, CertificateRequest, CertificateResponse,
    CertificateResult, SessionStatus, SessionStatusResult,
};

/// Mobile-ID client.
pub struct MobileIdClient<'a> {
    endpoint_url: String,
    custom_headers: HeaderMap,
    ssl_pinned_public_keys: Option<&'a Certificate>,
    polling_sleep_timeout_seconds: i32,
    long_polling_timeout_seconds: i32,
}

impl<'a> MobileIdClient<'a> {
    fn is_ssl_pinned(&self) -> bool {
        self.ssl_pinned_public_keys.is_some()
    }

    /// Get certificate from MID for Phone.
    pub async fn get_certificate(
        &self,
        request: &CertificateRequest,
    ) -> Result<CertificateResponse, MobileIdError> {
        println!("Getting certificate for phone number: {:?}", request);
        let url = format!("{}/certificate", self.endpoint_url.trim_end_matches("/"));
        match self
            .post_request::<CertificateRequest, CertificateResponse>(url.as_str(), request)
            .await
        {
            Ok(response) => {
                if response.result.is_some() && response.error.is_none() {
                    match response.to_owned().result.unwrap() {
                        CertificateResult::Ok => Ok(response),
                        CertificateResult::NotFound => Err(MidNotMidClient(
                            "No certificate for the user were found".to_string(),
                        )),
                    }
                } else {
                    Err(MidInternalError(format!(
                        "MID response {}",
                        response.to_owned().error.unwrap()
                    )))
                }
            }
            Err(error) => Err(MidInternalError(error.to_string())),
        }
    }

    /// Sends authentication request to MID and returns session ID.
    pub async fn send_authentication_request(
        &self,
        request: &AuthenticationRequest,
    ) -> Result<AuthenticationResponse, MobileIdError> {
        let url = format!(
            "{}/authentication",
            self.endpoint_url.clone().trim_end_matches("/")
        );
        self.post_request::<AuthenticationRequest, AuthenticationResponse>(url.as_str(), request)
            .await
    }

    /// Gets the authentication session status.
    pub async fn get_authentication_session_status(
        &self,
        session_id: String,
        session_status_response_socket_timeout_ms: Option<i32>,
    ) -> Result<SessionStatus, MobileIdError> {
        let mut url = format!(
            "{}/authentication/session/{}",
            self.endpoint_url.trim_end_matches("/"),
            session_id
        );
        let mut query_params = Vec::new();
        if let Some(timeout_ms) = session_status_response_socket_timeout_ms {
            query_params.push(format!("timeoutMs={}", timeout_ms));
        }
        if !query_params.is_empty() {
            let query_string = query_params.join("&");
            url = format!("{}?{}", url, query_string);
        }
        let session_status = self.get_request::<SessionStatus>(&url).await.unwrap();
        self.validate_result(session_status.clone()).unwrap();
        Ok(session_status.clone())
    }

    /// Generic POST request method
    async fn post_request<T, U>(&self, url: &str, body: &T) -> Result<U, MobileIdError>
    where
        T: Serialize,
        U: Clone + Serialize + DeserializeOwned + 'a,
    {
        let json = serde_json::to_string(body).unwrap();
        println!("POST {} contents: {}", url, json);
        let client = self.build_http_client();
        let request = client.post(url).json(body).build().unwrap();

        let response = client
            .execute(request)
            .await
            .map_err(|err| MidInternalError(err.to_string()))
            .unwrap();
        let http_status_code = response.status().as_u16();
        let response_json = response.json::<U>().await.unwrap();
        self.handle_http_status_code(http_status_code, response_json)
    }

    /// Builds HTTP client with or without SSL pinning
    fn build_http_client(&self) -> Client {
        if self.is_ssl_pinned() && self.ssl_pinned_public_keys.is_some() {
            let http_client = Client::builder()
                .default_headers(self.custom_headers.clone())
                .add_root_certificate(self.ssl_pinned_public_keys.clone().unwrap().clone())
                .build()
                .unwrap();
            http_client
        } else {
            let http_client = Client::builder()
                .default_headers(self.custom_headers.clone())
                .build()
                .unwrap();
            http_client
        }
    }

    /// Handles HTTP status code and returns either response or error
    fn handle_http_status_code<U>(
        &self,
        http_status_code: u16,
        response_type: U,
    ) -> Result<U, MobileIdError>
    where
        U: Clone + ToOwned + Serialize + DeserializeOwned,
    {
        match http_status_code {
            200 => Ok(response_type),
            429 => Err(MidLimitExceeded),
            403 => Err(MidForbidden),
            580 => Err(MidSystemUnderMaintenance),
            480 => Err(MidClientOld),
            472 => Err(MidPersonShouldViewAppOrSelfServicePortalNow),
            471 => Err(MidNoSuitableAccountFound),
            401 => Err(MidUnauthorized),
            503 => Err(MidServiceUnavailable),
            400 | 405 => Err(MidInternalError(
                serde_json::to_value(response_type.clone())
                    .unwrap()
                    .get("error")
                    .unwrap()
                    .to_string(),
            )),
            _ => Err(MidInternalError(format!(
                "Response was '{}', status code was {}",
                serde_json::to_string(&response_type).unwrap(),
                http_status_code
            ))),
        }
    }

    /// Generic GET request method
    async fn get_request<U>(&self, url: &str) -> Result<U, MobileIdError>
    where
        U: Clone + Serialize + DeserializeOwned + 'a,
    {
        let client = self.build_http_client();
        let request = client.get(url).build().unwrap();

        let response = client
            .execute(request)
            .await
            .map_err(|err| MidInternalError(err.to_string()))
            .unwrap();
        let http_status_code = response.status().as_u16();
        let response_json = response.json::<U>().await.unwrap();
        self.handle_http_status_code(http_status_code, response_json)
    }
    /// Fetches final session status. If session is not complete, then polls for session status until it is complete.
    pub async fn fetch_final_session_status(&self, session_id: String) -> SessionStatus {
        let mut session_status = self
            .poll_session_status(session_id.to_owned())
            .await
            .unwrap();
        while session_status.is_complete() || session_status.get_state() == RUNNING {
            session_status = self
                .poll_session_status(session_id.to_owned())
                .await
                .unwrap();
            if session_status.is_complete() {
                return session_status;
            }

            println!(
                "{}",
                format!(
                    "Sleeping for {} seconds",
                    self.polling_sleep_timeout_seconds
                )
            );
            thread::sleep(Duration::from_secs(
                self.polling_sleep_timeout_seconds as u64,
            ));
        }
        session_status.to_owned().clone()
    }

    /// Polls for session status
    async fn poll_session_status(
        &self,
        session_id: String,
    ) -> Result<SessionStatus, MobileIdError> {
        println!("Polling session status");
        self.get_authentication_session_status(
            session_id.to_owned(),
            Some(self.long_polling_timeout_seconds),
        )
        .await
    }

    /// Validates session status result
    fn validate_result(
        &self,
        session_status: SessionStatus,
    ) -> Result<SessionStatusResult, MobileIdError> {
        let result = session_status.result;
        if result.is_none() {
            return Err(MidInternalError(
                "Result is missing in the session status response".to_string(),
            ));
        } else {
            let result = result.unwrap();
            match result {
                SessionStatusResult::Ok => Ok(result),
                SessionStatusResult::Timeout | SessionStatusResult::ExpiredTransaction => {
                    println!("Session timeout");
                    Err(MidSessionTimeout)
                }
                SessionStatusResult::NotMidClient => {
                    println!("User is not Mobile-ID client");
                    Err(MidNotMidClient("User is not Mobile-ID client".to_string()))
                }
                SessionStatusResult::UserCancelled => {
                    println!("User cancelled the operation");
                    Err(MidUserCancelled)
                }
                SessionStatusResult::PhoneAbsent => {
                    println!("Sim not available");
                    Err(MidPhoneAbsent)
                }
                SessionStatusResult::SignatureHashMismatch => {
                    println!("Hash does not match with certificate type");
                    Err(MidSignatureHashMismatch)
                }
                SessionStatusResult::SimError | SessionStatusResult::DeliveryError => {
                    println!("SMS sending or SIM error");
                    Err(MidSimError)
                }
                _ => Err(MidInternalError(format!("Unknown error: {}", result))),
            }
        }
    }
}
