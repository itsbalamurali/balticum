use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use reqwest::{Certificate, Client, StatusCode};
use reqwest::header::HeaderMap;
use serde::de::DeserializeOwned;
use serde::Serialize;
use crate::mobile_id::errors::MobileIdError;
use crate::mobile_id::errors::MobileIdError::{MidInternalError, MidNotMidClient, MidServiceUnavailable, MidUnauthorized};
use crate::mobile_id::models::{AuthenticationRequest, AuthenticationResponse, CertificateRequest, CertificateResponse, CertificateResult, SessionStatus, SessionStatusState};
use crate::mobile_id::models::SessionStatusState::RUNNING;
use crate::smart_id::models::SessionStatusRequest;

const AUTHENTICATION_PATH: &str = "/authentication";
const DEFAULT_POLLING_SLEEP_TIMEOUT_SECONDS: i32 = 1000;
const RESPONSE_ERROR_CODES: [(i32, &str); 7] = [
    (503, "Limit exceeded"),
    (403, "Forbidden!"),
    (401, "Unauthorized"),
    (580, "System is under maintenance, retry later"),
    (480, "The client is old and not supported any more. Relying Party must contact customer support."),
    (472, "Person should view app or self-service portal now."),
    (471, "No suitable account of requested type found, but user has some other accounts."),
];

pub struct MobileIdClient {
    endpoint_url: String,
    network_interface: String,
    relying_party_uuid: String,
    relying_party_name: String,
    custom_headers: HeaderMap,
    ssl_pinned_public_keys: Option<Certificate>,
    polling_sleep_timeout_seconds: i32,
    long_polling_timeout_seconds: i32,
}

impl MobileIdClient {



    // async fn send_authentication_request(
    //     &self,
    //     request: &AuthenticationRequest,
    // ) -> Result<String, MobileIdError> {
    //     let endpoint = "authentication";
    //     self.send_request(request, endpoint).await
    // }
    //
    // async fn send_certificate_request(
    //     &self,
    //     request: &CertificateRequest,
    // ) -> Result<String, MobileIdError> {
    //     let endpoint = "certificate";
    //     self.send_request(request, endpoint).await
    // }
    //
    fn is_ssl_pinned(&self) -> bool {
        self.ssl_pinned_public_keys.is_some()
    }

    pub async fn get_certificate(&self, request: &CertificateRequest) -> Result<CertificateResponse, MobileIdError> {
        println!("Getting certificate for phone number: {:?}", request);
        let url = format!("{}/certificate", self.endpoint_url);
        match self.post_request::<CertificateRequest,CertificateResponse>(url.as_str(), request).await {
                Ok(response) => {
                    self.validate_certificate_result(response)
            },
            Err(error) => {
                Err(MidInternalError(error.to_string()))
            }
        }
    }

    pub async fn send_authentication_request(&self, request: &AuthenticationRequest) -> Result<AuthenticationResponse, MobileIdError> {
        let url = format!("{}/authentication", self.endpoint_url.clone());
         self.post_request::<AuthenticationRequest, AuthenticationResponse>(url.as_str(), request).await
    }

    pub async fn get_authentication_session_status(&self, request: SessionStatusRequest, session_status_response_socket_timeout_ms:Option<u64>) -> Result<SessionStatus, MobileIdError> {
        let mut url = format!("{}/authentication/session/{}", self.endpoint_url, request.session_id);
        let mut query_params = Vec::new();
        if let Some(timeout_ms) = session_status_response_socket_timeout_ms {
            query_params.push(format!("timeoutMs={}", timeout_ms));
        }
        if !query_params.is_empty() {
            let query_string = query_params.join("&");
            url = format!("{}?{}", url, query_string);
        }
        let session_status = self.get_request::<SessionStatus>(&url).await.unwrap();
        self.validate_result(session_status.clone());
        Ok(session_status)
    }

    fn validate_certificate_result(&self, response: CertificateResponse) -> Result<CertificateResponse, MobileIdError> {
        if response.result.is_some() && response.error.is_none() {
            match response.result.unwrap() {
                CertificateResult::Ok => Ok(response),
                CertificateResult::NotFound => {
                    Err(MidNotMidClient("No certificate for the user were found".to_string()))
                }
            }
        }
        else {
            Err(MidInternalError(format!("MID response {}", response.error.unwrap())))
        }
    }

    async fn post_request<T,U>(&self, url: &str, body: &T) -> Result<U, MobileIdError> where
        T: Serialize, U: DeserializeOwned {
        let json = serde_json::to_string(body).unwrap();
        println!("POST {} contents: {}", url, json);

        let client = if self.is_ssl_pinned() && self.ssl_pinned_public_keys.is_some() {
            let http_client = Client::builder()
                .default_headers(self.custom_headers.clone())
                .add_root_certificate(self.ssl_pinned_public_keys.clone().unwrap())
                .build().unwrap();
            http_client
        } else {
            let http_client = Client::builder()
                .default_headers(self.custom_headers.clone())
                .build().unwrap();
            http_client
        };

        let request = client
            .post(url)
            .json(body)
            .build()
            .unwrap();

        let response = client.execute(request).await.map_err(|err| MidInternalError(err.to_string())).unwrap();
        let http_status_code = response.status().as_u16();
        let response_text = response.text().await.unwrap();
        let response_json = response.json::<U>().await.unwrap();

        match http_status_code {
            200 => Ok(response_json),
            //TODO: 400 is returned when the request is invalid, 405 when the method is not allowed
            // Figure out how to handle this
            //400 | 405 => Err(MidInternalError(response_json.get("error").unwrap().to_string())),
            401 => Err(MidUnauthorized),
            503 => Err(MidServiceUnavailable),
            _ => {
                Err(MidInternalError(format!("Response was '{}', status code was {}", response_text, http_status_code)))
            }
        }
    }

    async fn get_request<U>(&self, url: &str) -> Result<U, MobileIdError> where U: DeserializeOwned {
        let client = if self.is_ssl_pinned() && self.ssl_pinned_public_keys.is_some() {
            let http_client = Client::builder()
                .default_headers(self.custom_headers.clone())
                .add_root_certificate(self.ssl_pinned_public_keys.clone().unwrap())
                .build().unwrap();
            http_client
        } else {
            let http_client = Client::builder()
                .default_headers(self.custom_headers.clone())
                .build().unwrap();
            http_client
        };
        let request = client
            .get(url)
            .build()
            .unwrap();

        let response = client.execute(request).await.map_err(|err| MidInternalError(err.to_string())).unwrap();
        let http_status_code = response.status().as_u16();
        let response_text = response.text().await.unwrap();
        let response_json = response.json::<U>().await.unwrap();
        match http_status_code {
            200 => Ok(response_json),
            400 | 405 => Err(MidInternalError(response_json.get("error").unwrap().to_string())),
            401 => Err(MidUnauthorized),
            503 => Err(MidServiceUnavailable),
            _ => {
                Err(MidInternalError(format!("Response was '{}', status code was {}", response_text, http_status_code)))
            }
        }
    }

    pub async fn fetch_final_signature_session_status(
        &self,
        session_id: String,
        long_poll_seconds: u64,
    ) -> SessionStatus {
        self.fetch_final_session_status(session_id, long_poll_seconds).await
    }

    pub async fn fetch_final_authentication_session(
        &self,
        session_id: String,
        long_poll_seconds: u64,
    ) -> SessionStatus {
        self.fetch_final_session_status(session_id, long_poll_seconds).await
    }

    pub async fn fetch_final_session_status(
        &self,
        session_id: String,
        long_poll_seconds: u64,
    ) -> SessionStatus {
        let mut session_status: Option<SessionStatus> = None;
        while session_status.is_none() || session_status.unwrap().get_state() == RUNNING
        {
            session_status = Some(self.poll_session_status(session_id.to_owned(), long_poll_seconds).await.unwrap());
            if let Some(status) = session_status {
                if status.is_complete() {
                    return status;
                }
            }

            println!("{}",format!(
                "Sleeping for {} seconds",
                self.polling_sleep_timeout_seconds
            ));
            thread::sleep(Duration::from_secs(self.polling_sleep_timeout_seconds as u64));
        }

        println!("Got session final session status response");
        session_status.to_owned().unwrap().clone()
    }


    async fn poll_session_status(
        &self,
        session_id: String,
        long_poll_seconds: u64,
    ) -> Result<SessionStatus, MobileIdError> {
        println!("Polling session status");
        let request = self.create_session_status_request(session_id, long_poll_seconds);
        self.pull_authentication_session_status(request,Some(10000)).await
    }

    fn create_session_status_request(
        &self,
        session_id: String,
        long_poll_seconds: u64,
    ) -> SessionStatusRequest {
        SessionStatusRequest{
            session_id,
            session_status_response_socket_timeout_ms: long_poll_seconds,
            network_interface: "".to_string(),
        }
    }

    fn validate_result(&self, session_status: SessionStatus) {
        let result = session_status.get_result();
        if result.is_none() {
            println!("Result is missing in the session status response");
            panic!("Result is missing in the session status response");
        } else {
            let result = result.unwrap().to_uppercase();
            match result.as_str() {
                "OK" => return,
                "TIMEOUT" | "EXPIRED_TRANSACTION" => {
                    println!("Session timeout");
                    panic!("Session timeout");
                }
                "NOT_MID_CLIENT" => {
                    println!("User is not Mobile-ID client");
                    panic!("User is not Mobile-ID client");
                }
                "USER_CANCELLED" => {
                    println!("User cancelled the operation");
                    panic!("User cancelled the operation");
                }
                "PHONE_ABSENT" => {
                    println!("Sim not available");
                    panic!("Sim not available");
                }
                "SIGNATURE_HASH_MISMATCH" => {
                    println!("Hash does not match with certificate type");
                    panic!("Hash does not match with certificate type");
                }
                "SIM_ERROR" | "DELIVERY_ERROR" => {
                    println!("SMS sending or SIM error");
                    panic!("SMS sending or SIM error");
                }
                _ => panic!("MID returned error code '{}'", result),
            }
        }
    }
}
