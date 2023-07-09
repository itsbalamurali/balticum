use base64::Engine;
use base64::engine::general_purpose;
use chrono::{NaiveDateTime};
use serde::{Deserialize, Serialize};

use strum::EnumString;
use x509_certificate::{X509Certificate};


use crate::smart_id::models::HashType;

#[derive(Debug, EnumString, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Language {
    EST,
    ENG,
    RUS,
    LIT,
    LAT,
}

#[derive(Debug, EnumString, Serialize, Deserialize)]
pub enum DisplayTextFormat {
    #[serde(rename = "GSM-7")]
    GSM7,
    #[serde(rename = "UCS-2")]
    UCS2,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    #[serde(rename = "relyingPartyName")]
    pub relying_party_name: String,
    #[serde(rename = "phoneNumber")]
    pub phone_number: String,
    #[serde(rename = "nationalIdentityNumber")]
    pub national_identity_number: String,
    pub hash: String,
    #[serde(rename = "hashType")]
    pub hash_type: HashType,
    pub language: Language,
    #[serde(rename = "displayText")]
    pub display_text: String,
    #[serde(rename = "displayTextFormat")]
    pub display_text_format: DisplayTextFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileIdSignature {
    #[serde(rename = "value")]
    pub value_in_base64: String,
    #[serde(rename = "algorithm")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<NaiveDateTime>,
    #[serde(rename="traceId", skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl SessionStatus {
    pub fn get_cert(self) -> Option<X509Certificate> {
        if self.cert.is_none() {
            return None;
        }
       Some(X509Certificate::from_der(general_purpose::STANDARD.decode(self.cert.unwrap()).unwrap().as_slice()).unwrap())
    }
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
    SignatureHashMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, EnumString, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SessionStatusState {
    INITIALIZED,
    RUNNING,
    COMPLETE,
    EXPIRED,
    ERROR,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    #[serde(rename = "sessionID", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
