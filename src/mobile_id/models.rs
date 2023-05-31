use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::EnumString;

use crate::mobile_id::errors::MobileIdError;
use crate::mobile_id::errors::MobileIdError::MissingOrInvalidParameter;
use crate::mobile_id::models::SessionStatusState::{COMPLETE, INITIALIZED};

#[derive(Debug, EnumString, Serialize, Deserialize)]
pub enum Language {
    EST,
    ENG,
    RUS,
    LIT,
    LAT,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    #[serde(rename = "relyingPartyUUID", skip_serializing_if = "Option::is_none")]
    pub relying_party_uuid: Option<String>,
    #[serde(rename = "relyingPartyName", skip_serializing_if = "Option::is_none")]
    pub relying_party_name: Option<String>,
    #[serde(rename = "phoneNumber")]
    pub phone_number: String,
    #[serde(rename = "nationalIdentityNumber")]
    pub national_identity_number: String,
    pub hash: String,
    #[serde(rename = "hashType")]
    pub hash_type: String,
    pub language: Language,
    #[serde(rename = "displayText")]
    pub display_text: Option<String>,
    #[serde(rename = "displayTextFormat")]
    pub display_text_format: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileIdSignature {
    #[serde(rename = "valueInBase64")]
    pub value_in_base64: String,
    #[serde(rename = "algorithmName")]
    pub algorithm_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub state: SessionStatusState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SessionStatusResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<MobileIdSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
}

#[derive(Debug, Clone, strum::Display, Copy, PartialEq, Serialize, EnumString, Deserialize)]
pub enum SessionStatusResult {
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "TIMEOUT")]
    Timeout,
    #[serde(rename = "NOT_MID_CLIENT")]
    NotMidClient,
    #[serde(rename = "PHONE_ABSENT")]
    PhoneAbsent,
    #[serde(rename = "SENDING_ERROR")]
    SendingError,
    #[serde(rename = "SIM_ERROR")]
    SimError,
    #[serde(rename = "DELIVERY_ERROR")]
    DeliveryError,
    #[serde(rename = "EXPIRED_TRANSACTION")]
    ExpiredTransaction,
    #[serde(rename = "USER_CANCELLED")]
    UserCancelled,
    #[serde(rename = "SIGNATURE_HASH_MISMATCH")]
    SignatureHashMismatch
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, EnumString, Deserialize)]
pub enum SessionStatusState {
    INITIALIZED,
    RUNNING,
    COMPLETE,
    EXPIRED,
    ERROR,
}

impl SessionStatus {
    pub fn new(values: Option<&Value>) -> Result<Self, MobileIdError> {
        let mut session_status = SessionStatus {
            state: INITIALIZED,
            result: None,
            signature: None,
            cert: None,
        };

        if let Some(values) = values {
            if let Some(signature_values) = values.get("signature").and_then(Value::as_object) {
                let algorithm = signature_values.get("algorithm").and_then(Value::as_str).unwrap_or("");
                let value = signature_values.get("value").and_then(Value::as_str).unwrap_or("");
                let signature = MobileIdSignature {
                    value_in_base64: value.to_string(),
                    algorithm_name: algorithm.to_string(),
                };
                session_status.signature = Some(signature);
            }
        }

        if session_status.cert.is_none() {
            return Err(MissingOrInvalidParameter("Certificate must be set.".to_string()));
        }

        Ok(session_status)
    }

    pub fn get_state(&self) -> SessionStatusState {
        self.state.clone()
    }

    pub fn set_state(&mut self, state: SessionStatusState) {
        self.state = state;
    }


    pub fn get_signature(&self) -> Option<&MobileIdSignature> {
        self.signature.as_ref()
    }

    pub fn set_signature(&mut self, signature: Option<MobileIdSignature>) {
        self.signature = signature;
    }

    pub fn get_cert(&self) -> Result<&str, MobileIdError> {
        self.cert.as_deref().ok_or_else(|| MissingOrInvalidParameter("Certificate must be set.".to_string()))
    }

    pub fn set_cert(&mut self, cert: Option<String>) {
        self.cert = cert;
    }

    pub fn is_complete(&self) -> bool {
        self.state == COMPLETE
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuthenticationResponse {
    pub fn new(response_json: &serde_json::Value) -> Self {
        let session_id = response_json["sessionID"].as_str()
            .or_else(|| response_json["sessionId"].as_str())
            .unwrap_or_default()
            .to_string();

        AuthenticationResponse {
            session_id,
            error: None,
        }
    }

    pub fn get_session_id(&self) -> &str {
        &self.session_id
    }

    pub fn set_session_id(&mut self, session_id: String) {
        self.session_id = session_id;
    }

    pub fn to_string(&self) -> String {
        format!("AuthenticationResponse{{sessionID='{}'}}", self.session_id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    #[serde(rename = "relyingPartyName")]
    pub relying_party_name: String,
    #[serde(rename = "phoneNumber")]
    pub phone_number: String,
    #[serde(rename = "nationalIdentityNumber")]
    pub national_identity_number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<CertificateResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
}

#[derive(Debug, Clone, EnumString, PartialEq, Serialize, Deserialize)]
pub enum CertificateResult {
    #[strum(serialize = "OK")]
    Ok,
    #[strum(serialize = "NOT_FOUND")]
    NotFound,
}