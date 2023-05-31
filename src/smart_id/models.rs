use std::error::Error;
use std::str::FromStr;
use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose;
use hex::ToHex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use strum::Display;
use strum::EnumString;
use thiserror::Error;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::X509Certificate;

use crate::smart_id::errors::Sma;
use crate::smart_id::errors::Sma::{InvalidParametersException, TechnicalError};
use crate::smart_id::verification_code_calculator::VerificationCodeCalculator;

#[derive(Error, Clone, Debug, Serialize, Deserialize)]
pub enum SmartIdAuthenticationResultError {
    #[error("Response end result verification failed.")]
    InvalidEndResult,
    #[error("Signature verification failed.")]
    SignatureVerificationFailure,
    #[error("Signer's certificate expired.")]
    CertificateExpired,
    #[error("Signer's certificate is not trusted.")]
    CertificateNotTrusted,
    #[error("Signer's certificate level does not match with the requested level.")]
    CertificateLevelMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartIdAuthenticationResult {
    pub authentication_identity: Option<AuthenticationIdentity>,
    pub valid: bool,
    pub errors: Vec<SmartIdAuthenticationResultError>,
}

impl SmartIdAuthenticationResult {
    pub fn new() -> Self {
        Self {
            authentication_identity: None,
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn set_authentication_identity(&mut self, authentication_identity: AuthenticationIdentity) {
        self.authentication_identity = Some(authentication_identity);
    }

    pub fn set_valid(&mut self, valid: bool) {
        self.valid = valid;
    }

    pub fn add_error(&mut self, error: SmartIdAuthenticationResultError) {
        self.errors.push(error);
    }
}

pub struct AuthenticationCertificate {
    pub name: String,
    pub subject: AuthenticationCertificateSubject,
    pub hash: String,
    pub issuer: AuthenticationCertificateIssuer,
    pub version: i32,
    pub serial_number: String,
    pub serial_number_hex: String,
    pub valid_from: String,
    pub valid_to: u64,
    pub valid_from_time_t: i32,
    pub valid_to_time_t: i32,
    pub signature_type_sn: String,
    pub signature_type_ln: String,
    pub signature_type_nid: i32,
    pub purposes: Vec<String>,
    pub extensions: Option<AuthenticationCertificateExtensions>,
}


pub struct AuthenticationCertificateExtensions {
    basic_constraints: String,
    key_usage: String,
    certificate_policies: String,
    subject_key_identifier: String,
    qc_statements: String,
    authority_key_identifier: String,
    authority_info_access: String,
    extended_key_usage: String,
    subject_alt_name: String,
}

pub struct AuthenticationCertificateIssuer {
    pub c: String,
    pub o: String,
    pub undef: String,
    pub cn: String,
}

pub struct AuthenticationCertificateSubject {
    //Country code
    pub c: String,
    //Country name
    pub o: String,
    //Organizational unit name
    pub ou: String,
    //Common name
    pub cn: String,
    //Surname
    pub sn: String,
    //Given name
    pub gn: String,
    //Serial number
    pub serial_number: String,
}

pub struct AuthenticationHash {
    pub data_to_sign: String,
    pub hash: String,
    pub hash_type: HashType,
}

impl AuthenticationHash {
    pub fn generate_random_hash(hash_type: HashType) -> Self {
        let random_bytes = Self::get_random_bytes();
        let mut authentication_hash = AuthenticationHash {
            data_to_sign: random_bytes.encode_hex::<String>(),
            hash: String::new(),
            hash_type,
        };
        authentication_hash.set_hash(&authentication_hash.calculate_hash());
        authentication_hash
    }

    fn calculate_hash(&self) -> String {
        return DigestCalculator::calculate_digest(&self.data_to_sign, self.hash_type.clone());
    }

    pub fn generate() -> Self {
        Self::generate_random_hash(HashType::Sha512)
    }

    fn get_random_bytes() -> Vec<u8> {
        let mut random_bytes = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        random_bytes
    }

    pub fn get_hash_type(&self) -> HashType {
        self.hash_type.clone()
    }

    pub fn get_data_to_sign(&self) -> &str {
        &self.data_to_sign
    }

    pub fn set_hash(&mut self, hash: &str) {
        self.hash = hash.to_string();
    }

    pub fn get_hash(&self) -> &str {
        &self.hash
    }

    pub fn calculate_verification_code(&self) -> String {
        VerificationCodeCalculator::calculate(&self.hash)
    }

    pub fn calculate_hash_in_base64(&self) -> String {
        let hash = self.calculate_hash();
        general_purpose::STANDARD
            .encode(hash.as_bytes())
    }
}


#[cfg(test)]
mod authentication_hash_tests {
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    #[test]
    fn generate_random_hash_of_type_sha512() {
        let authentication_hash = AuthenticationHash::generate_random_hash(HashType::Sha512);
        assert_eq!(HashType::Sha512, authentication_hash.get_hash_type());
        assert_eq!(
            STANDARD.decode(&authentication_hash.calculate_hash_in_base64()).unwrap(),
            authentication_hash.get_hash().as_bytes().to_vec()
        );
    }

    #[test]
    fn generate_random_hash_of_type_sha384() {
        let authentication_hash = AuthenticationHash::generate_random_hash(HashType::Sha384);
        assert_eq!(HashType::Sha384, authentication_hash.get_hash_type());
        assert_eq!(
            STANDARD.decode(&authentication_hash.calculate_hash_in_base64()).unwrap(),
            authentication_hash.get_hash().as_bytes().to_vec()
        );
    }

    #[test]
    fn generate_random_hash_of_type_sha256() {
        let authentication_hash = AuthenticationHash::generate_random_hash(HashType::Sha256);
        assert_eq!(HashType::Sha256, authentication_hash.get_hash_type());
        assert_eq!(
            STANDARD.decode(&authentication_hash.calculate_hash_in_base64()).unwrap(),
            authentication_hash.get_hash().as_bytes().to_vec()
        );
    }
}


#[derive(Debug,Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationSessionRequest {
    #[serde(rename = "relyingPartyUUID")]
    relying_party_uuid: String,
    relying_party_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_interface: Option<String>,
    certificate_level: CertificateLevel,
    hash: String,
    hash_type: HashType,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    allowed_interactions_order: Vec<Interaction>,
}

#[derive(Debug,Clone,Default,PartialEq,EnumString, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CertificateLevel {
    #[strum(serialize = "QUALIFIED")]
    #[default]
    Qualified,
    #[strum(serialize = "ADVANCED")]
    Advanced,
    #[strum(serialize = "QSCD")]
    Qscd,
}

impl CertificateLevel {
    pub fn is_equal_or_above(&self, certificate_level: &str) -> bool {
        if self == &CertificateLevel::from_str(certificate_level).unwrap() {
            true
        } else {
            match (certificate_level.parse().unwrap(), &self) {
                (CertificateLevel::Advanced, CertificateLevel::Advanced)
                | (CertificateLevel::Qualified, CertificateLevel::Qualified)
                | (CertificateLevel::Qualified, CertificateLevel::Advanced) => true,
                _ => false,
            }
        }
    }
}

impl AuthenticationSessionRequest {
    pub fn new(relying_party_uuid: String, relying_party_name: String, hash: String, hash_type: HashType) -> Self {
        AuthenticationSessionRequest {
            relying_party_uuid,
            relying_party_name,
            network_interface: None,
            certificate_level: CertificateLevel::Qualified,
            hash: hash,
            hash_type,
            nonce: None,
            allowed_interactions_order: Vec::new(),
        }
    }

    pub fn set_relying_party_uuid(&mut self, relying_party_uuid: &str) {
        self.relying_party_uuid = relying_party_uuid.to_string();
    }

    pub fn get_relying_party_uuid(&self) -> &str {
        &self.relying_party_uuid
    }

    pub fn set_relying_party_name(&mut self, relying_party_name: &str) {
        self.relying_party_name = relying_party_name.to_string();
    }

    pub fn get_relying_party_name(&self) -> &str {
        &self.relying_party_name
    }

    pub fn set_network_interface(&mut self, network_interface: String) {
        self.network_interface = Some(network_interface);
    }

    pub fn get_network_interface(&self) -> Option<&str> {
        self.network_interface.as_deref()
    }

    pub fn set_certificate_level(&mut self, certificate_level:CertificateLevel) {
        self.certificate_level = certificate_level;
    }

    pub fn get_certificate_level(&self) -> CertificateLevel {
        self.certificate_level.clone()
    }

    pub fn set_hash(&mut self, hash: &str) {
        self.hash = hash.to_string();
    }

    pub fn get_hash(&self) -> &str {
        &self.hash
    }

    pub fn set_hash_type(&mut self, hash_type: HashType) {
        self.hash_type = hash_type;
    }

    pub fn get_hash_type(&self) -> HashType {
        self.hash_type.clone()
    }

    pub fn set_nonce(&mut self, nonce: String) {
        self.nonce = Some(nonce.to_string());
    }

    pub fn get_nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    pub fn set_allowed_interactions_order(
        &mut self,
        allowed_interactions_order: Vec<Interaction>,
    ) {
        self.allowed_interactions_order = allowed_interactions_order;
    }

    pub fn get_allowed_interactions_order(&self) -> &Vec<Interaction> {
        &self.allowed_interactions_order
    }

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSessionResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

pub struct CertificateParser;

impl CertificateParser {
    //let certificate_bytes = CertificateParser::get_der_certificate(certificate_value).unwrap();

    pub fn parse_x509_certificate(certificate: &[u8]) -> Result<X509Certificate, anyhow::Error> {
        let (rest, parsed_cert) = parse_x509_certificate(certificate).unwrap();
        if !rest.is_empty() {
            return Err(anyhow!("Failed to parse the entire X.509 certificate"));
        }
        Ok(parsed_cert)
    }

    pub fn get_der_certificate(certificate_value: String) -> Result<Vec<u8>, Box<dyn Error>> {
        let certificate_value = certificate_value.trim();
        let begin_cert = "-----BEGIN CERTIFICATE-----";
        let end_cert = "-----END CERTIFICATE-----";

        if certificate_value.starts_with(begin_cert) && certificate_value.ends_with(end_cert) {
            let base64_cert = &certificate_value[begin_cert.len()..certificate_value.len() - end_cert.len()];
            let base64_decoded = general_purpose::STANDARD
                .decode(base64_cert).unwrap();
            Ok(base64_decoded)
        } else {
            Err("Invalid certificate format: missing BEGIN_CERT or END_CERT".into())
        }
    }
}

pub struct DigestCalculator;

impl DigestCalculator {
    pub fn calculate_digest(data_to_digest: &str, hash_type: HashType) -> String {
        use openssl::hash::{hash, MessageDigest};
        let message_digest = match hash_type {
            HashType::Md5 => MessageDigest::md5(),
            HashType::Sha1 => MessageDigest::sha1(),
            HashType::Sha256 => MessageDigest::sha256(),
            HashType::Sha384 => MessageDigest::sha384(),
            HashType::Sha512 => MessageDigest::sha512(),
            _ => panic!("Unsupported hash type: {}", hash_type),
        };
        hash(message_digest, data_to_digest.as_bytes())
            .unwrap()
            .encode_hex()
    }
}

#[derive(Display,Default, Debug, Clone, PartialEq, EnumString, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    #[default]
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Interaction {
    #[serde(rename = "type")]
    interaction_type: InteractionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_text60: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_text200: Option<String>,
}

impl Interaction {
    pub fn of_type_display_text_and_pin(display_text60: String) -> Interaction {
        Interaction {
            interaction_type: InteractionType::DisplayTextAndPIN,
            display_text60: Some(display_text60),
            display_text200: None,
        }
    }

    pub fn of_type_verification_code_choice(display_text60: String) -> Interaction {
        Interaction {
            interaction_type: InteractionType::VerificationCodeChoice,
            display_text60: Some(display_text60),
            display_text200: None,
        }
    }

    pub fn of_type_confirmation_message(display_text200: String) -> Interaction {
        Interaction {
            interaction_type: InteractionType::ConfirmationMessage,
            display_text60: None,
            display_text200: Some(display_text200),
        }
    }

    pub fn of_type_confirmation_message_and_verification_code_choice(
        display_text200: String,
    ) -> Interaction {
        Interaction {
            interaction_type: InteractionType::ConfirmationMessageAndVerificationCodeChoice,
            display_text60: None,
            display_text200: Some(display_text200),
        }
    }

    pub fn to_array(&self) -> serde_json::Value {
        let mut interaction = serde_json::json!({
            "type": self.interaction_type.as_str(),
        });

        if let Some(display_text60) = &self.display_text60 {
            interaction["displayText60"] = serde_json::Value::String(display_text60.clone());
        } else if let Some(display_text200) = &self.display_text200 {
            interaction["displayText200"] = serde_json::Value::String(display_text200.clone());
        }

        interaction
    }

    pub fn validate(&self) -> Result<(), Sma> {
        match self.interaction_type {
            InteractionType::DisplayTextAndPIN | InteractionType::VerificationCodeChoice => {
                if let Some(display_text60) = &self.display_text60 {
                    if display_text60.len() > 60 {
                        return Err(InvalidParametersException(
                            "Interactions of type displayTextAndPIN and verificationCodeChoice require displayTexts with length 60 or less".to_string(),
                        ));
                    }
                }
            }
            InteractionType::ConfirmationMessage
            | InteractionType::ConfirmationMessageAndVerificationCodeChoice => {
                if let Some(display_text200) = &self.display_text200 {
                    if display_text200.len() > 200 {
                        return Err(InvalidParametersException(
                            "Interactions of type confirmationMessage and confirmationMessageAndVerificationCodeChoice require displayTexts with length 200 or less".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone,EnumString, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[strum(serialize_all = "camelCase")]
pub enum InteractionType {
    DisplayTextAndPIN,
    VerificationCodeChoice,
    ConfirmationMessage,
    ConfirmationMessageAndVerificationCodeChoice,
}

impl InteractionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            InteractionType::DisplayTextAndPIN => "displayTextAndPIN",
            InteractionType::VerificationCodeChoice => "verificationCodeChoice",
            InteractionType::ConfirmationMessage => "confirmationMessage",
            InteractionType::ConfirmationMessageAndVerificationCodeChoice => {
                "confirmationMessageAndVerificationCodeChoice"
            }
        }
    }
}

pub struct SemanticsIdentifier {
    semantics_identifier: String, // https://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.01_60/en_31941201v010101p.pdf in chapter 5.1.3
}

impl SemanticsIdentifier {
    pub fn from_string(semantics_identifier: String) -> SemanticsIdentifier {
        SemanticsIdentifier {
            semantics_identifier,
        }
    }

    pub fn builder() -> SemanticsIdentifierBuilder {
        SemanticsIdentifierBuilder::new()
    }

    pub fn as_string(&self) -> &str {
        &self.semantics_identifier
    }

    pub fn validate(&self) -> Result<(), Sma> {
        let regex = regex::Regex::new(r"^[A-Z\:]{5}-[a-zA-Z\d\-]{5,30}$").unwrap();
        if !regex.is_match(&self.semantics_identifier) {
            return Err(InvalidParametersException(format!(
                "The semantics identifier '{}' has an invalid format",
                &self.semantics_identifier
            )));
        }
        Ok(())
    }
}

pub struct SemanticsIdentifierBuilder {
    semantics_identifier_type: Option<String>,
    country_code: Option<String>,
    identifier: Option<String>,
}

impl SemanticsIdentifierBuilder {
    pub fn new() -> SemanticsIdentifierBuilder {
        SemanticsIdentifierBuilder {
            semantics_identifier_type: None,
            country_code: None,
            identifier: None,
        }
    }

    pub fn with_semantics_identifier_type(
        mut self,
        semantics_identifier_type: String,
    ) -> SemanticsIdentifierBuilder {
        self.semantics_identifier_type = Some(semantics_identifier_type);
        self
    }

    pub fn with_country_code(mut self, country_code: String) -> SemanticsIdentifierBuilder {
        self.country_code = Some(country_code);
        self
    }

    pub fn with_identifier(mut self, identifier: String) -> SemanticsIdentifierBuilder {
        self.identifier = Some(identifier);
        self
    }

    pub fn build(&self) -> Result<SemanticsIdentifier, String> {
        let semantics_identifier_type = self
            .semantics_identifier_type
            .clone()
            .ok_or("Semantics identifier type is missing")?;
        let country_code = self.country_code.clone().ok_or("Country code is missing")?;
        let identifier = self.identifier.clone().ok_or("Identifier is missing")?;
        let semantics_identifier_string = format!(
            "{}{}-{}",
            semantics_identifier_type, country_code, identifier
        );
        Ok(SemanticsIdentifier::from_string(
            semantics_identifier_string,
        ))
    }
}

pub struct SemanticsIdentifierTypes;

impl SemanticsIdentifierTypes {
    pub const PNO: &'static str = "PNO";
    pub const PAS: &'static str = "PAS";
    pub const IDC: &'static str = "IDC";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCertificate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) certificate_level: Option<String>,
}

impl SessionCertificate {
    pub fn new() -> SessionCertificate {
        SessionCertificate {
            value: None,
            certificate_level: None,
        }
    }

    pub fn set_value(&mut self, value: String) {
        self.value = Some(value);
    }

    pub fn get_value(&self) -> Option<String> {
        self.value.clone()
    }

    pub fn set_certificate_level(&mut self, certificate_level: String) {
        self.certificate_level = Some(certificate_level);
    }

    pub fn get_certificate_level(&self) -> Option<String> {
        self.certificate_level.clone()
    }
}

#[derive(Debug, PartialEq, EnumString, Display, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionEndResultCode {
    #[strum(serialize = "OK")]
    #[serde(rename = "OK")]
    Ok,
    #[strum(serialize = "USER_REFUSED")]
    #[serde(rename = "USER_REFUSED")]
    UserRefused,
    #[strum(serialize = "TIMEOUT")]
    #[serde(rename = "TIMEOUT")]
    Timeout,
    #[strum(serialize = "DOCUMENT_UNUSABLE")]
    #[serde(rename = "DOCUMENT_UNUSABLE")]
    DocumentUnusable,
    #[strum(serialize = "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP")]
    #[serde(rename = "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP")]
    RequiredInteractionNotSupportedByApp,
    #[strum(serialize = "USER_REFUSED_DISPLAYTEXTANDPIN")]
    #[serde(rename = "USER_REFUSED_DISPLAYTEXTANDPIN")]
    UserRefusedDisplayTextAndPIN,
    #[strum(serialize = "USER_REFUSED_VC_CHOICE")]
    #[serde(rename = "USER_REFUSED_VC_CHOICE")]
    UserRefusedVCChoice,
    #[strum(serialize = "USER_REFUSED_CONFIRMATIONMESSAGE")]
    #[serde(rename = "USER_REFUSED_CONFIRMATIONMESSAGE")]
    UserRefusedConfirmationMessage,
    #[strum(serialize = "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE")]
    #[serde(rename = "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE")]
    UserRefusedConfirmationMessageWithVCChoice,
    #[strum(serialize = "USER_REFUSED_CERT_CHOICE")]
    #[serde(rename = "USER_REFUSED_CERT_CHOICE")]
    UserRefusedCertChoice,
    #[strum(serialize = "WRONG_VC")]
    #[serde(rename = "WRONG_VC")]
    WrongVC,
}

// impl SessionEndResultCode {
//     pub const OK: &'static str = "OK";
//     pub const USER_REFUSED: &'static str = "USER_REFUSED";
//     pub const TIMEOUT: &'static str = "TIMEOUT";
//     pub const DOCUMENT_UNUSABLE: &'static str = "DOCUMENT_UNUSABLE";
//     pub const REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP: &'static str =
//         "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP";
//     pub const USER_REFUSED_DISPLAYTEXTANDPIN: &'static str = "USER_REFUSED_DISPLAYTEXTANDPIN";
//     pub const USER_REFUSED_VC_CHOICE: &'static str = "USER_REFUSED_VC_CHOICE";
//     pub const USER_REFUSED_CONFIRMATIONMESSAGE: &'static str = "USER_REFUSED_CONFIRMATIONMESSAGE";
//     pub const USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE: &'static str =
//         "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE";
//     pub const USER_REFUSED_CERT_CHOICE: &'static str = "USER_REFUSED_CERT_CHOICE";
//     pub const WRONG_VC: &'static str = "WRONG_VC";
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResult {
    pub end_result: SessionEndResultCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_number: Option<String>,
}

impl SessionResult {
    pub fn new(end_result: SessionEndResultCode) -> SessionResult {
        SessionResult {
            end_result,
            document_number: None,
        }
    }

    pub fn set_document_number(&mut self, document_number: String) {
        self.document_number = Some(document_number);
    }

    pub fn get_document_number(&self) -> Option<&String> {
        self.document_number.as_ref()
    }

    pub fn get_end_result(&self) -> SessionEndResultCode {
        self.end_result.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSignature {
    pub algorithm: Option<String>,
    pub value: Option<String>,
}

impl SessionSignature {
    pub fn new() -> SessionSignature {
        SessionSignature {
            algorithm: None,
            value: None,
        }
    }

    pub fn set_algorithm(&mut self, algorithm: String) {
        self.algorithm = Some(algorithm);
    }

    pub fn get_algorithm(&self) -> Option<String> {
        self.algorithm.clone()
    }

    pub fn set_value(&mut self, value: String) {
        self.value = Some(value);
    }

    pub fn get_value(&self) -> Option<String> {
        self.value.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub state: SessionStatusCode,
    pub result: Option<SessionResult>,
    pub signature: Option<SessionSignature>,
    pub cert: Option<SessionCertificate>,
    pub ignored_properties: Option<Vec<String>>,
    pub interaction_flow_used: Option<String>,
}

impl SessionStatus {
    pub fn new() -> SessionStatus {
        SessionStatus {
            state: SessionStatusCode::RUNNING,
            result: None,
            signature: None,
            cert: None,
            ignored_properties: None,
            interaction_flow_used: None,
        }
    }

    pub fn set_state(&mut self, state: SessionStatusCode) {
        self.state = state;
    }

    pub fn set_result(&mut self, result: Option<SessionResult>) {
        self.result = result;
    }

    pub fn set_signature(&mut self, signature: Option<SessionSignature>) {
        self.signature = signature;
    }

    pub fn set_cert(&mut self, cert: Option<SessionCertificate>) {
        self.cert = cert;
    }

    pub fn set_ignored_properties(&mut self, ignored_properties: Option<Vec<String>>) {
        self.ignored_properties = ignored_properties;
    }

    pub fn set_interaction_flow_used(&mut self, interaction_flow_used: Option<String>) {
        self.interaction_flow_used = interaction_flow_used;
    }

    pub fn get_state(&self) -> SessionStatusCode {
        self.state.clone()
    }

    pub fn get_result(&self) -> Option<SessionResult> {
        self.result.clone()
    }

    pub fn get_signature(&self) -> Option<&SessionSignature> {
        self.signature.as_ref()
    }

    pub fn get_cert(&self) -> Option<&SessionCertificate> {
        self.cert.as_ref()
    }

    pub fn get_ignored_properties(&self) -> Option<&Vec<String>> {
        self.ignored_properties.as_ref()
    }

    pub fn get_interaction_flow_used(&self) -> Option<&str> {
        self.interaction_flow_used.as_deref()
    }

    pub fn is_running_state(&self) -> bool {
        self.state == SessionStatusCode::RUNNING
    }
}

#[derive(Display, Clone, Debug, PartialEq, EnumString, Serialize, Deserialize)]
pub enum SessionStatusCode {
    RUNNING,
    COMPLETE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStatusRequest {
    pub session_id: String,
    pub session_status_response_socket_timeout_ms: u64,
    pub network_interface: String,
}

impl SessionStatusRequest {
    pub fn new(session_id: String) -> SessionStatusRequest {
        SessionStatusRequest {
            session_id,
            session_status_response_socket_timeout_ms: 1000,
            network_interface: String::new(),
        }
    }

    pub fn set_session_status_response_socket_timeout_ms(
        &mut self,
        session_status_response_socket_timeout_ms: u64,
    ) {
        self.session_status_response_socket_timeout_ms = session_status_response_socket_timeout_ms;
    }

    pub fn is_session_status_response_socket_timeout_set(&self) -> bool {
        self.session_status_response_socket_timeout_ms > 0
    }

    pub fn set_network_interface(&mut self, network_interface: String) {
        self.network_interface = network_interface;
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut json_obj = serde_json::json!({});

        let timeout_ms = self.session_status_response_socket_timeout_ms;
        json_obj["timeoutMs"] = serde_json::Value::Number(serde_json::Number::from(timeout_ms));

        let network_interface = &self.network_interface;
        json_obj["networkInterface"] = serde_json::Value::String(network_interface.clone());

        json_obj
    }
}

pub struct SignableData {
    pub data_to_sign: String,
    pub hash_type: HashType,
}

impl SignableData {
    pub fn new(data_to_sign: String) -> SignableData {
        SignableData {
            data_to_sign,
            hash_type: HashType::Sha512,
        }
    }

    pub fn calculate_hash_in_base64(&self) -> String {
        let digest = self.calculate_hash();
        general_purpose::STANDARD.encode(&digest)
    }

    pub fn calculate_hash(&self) -> Vec<u8> {
        DigestCalculator::calculate_digest(&self.data_to_sign, self.hash_type.clone()).into_bytes()
    }

    pub fn set_hash_type(&mut self, hash_type: HashType) {
        self.hash_type = hash_type;
    }

    pub fn get_hash_type(&self) -> &HashType {
        &self.hash_type
    }

    pub fn are_fields_filled(&self) -> bool {
        !self.data_to_sign.is_empty()
    }

    pub fn get_data_to_sign(&self) -> &str {
        &self.data_to_sign
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartIdAuthenticationResponse {
    pub end_result: SessionEndResultCode,
    pub signed_data: String,
    pub value_in_base64: String,
    pub algorithm_name: Option<String>,
    pub certificate: String,
    pub requested_certificate_level: Option<String>,
    pub certificate_level: String,
    pub state: SessionStatusCode,
    pub ignored_properties: Option<Vec<String>>,
    pub interaction_flow_used: Option<String>,
    pub document_number: Option<String>,
}

impl SmartIdAuthenticationResponse {
    pub fn new() -> SmartIdAuthenticationResponse {
        SmartIdAuthenticationResponse {
            end_result: SessionEndResultCode::Ok,
            signed_data: String::new(),
            value_in_base64: String::new(),
            algorithm_name: None,
            certificate: String::new(),
            requested_certificate_level: None,
            certificate_level: String::new(),
            state: SessionStatusCode::RUNNING,
            ignored_properties: None,
            interaction_flow_used: None,
            document_number: None,
        }
    }

    pub fn get_end_result(&self) -> SessionEndResultCode {
        self.end_result.clone()
    }

    pub fn set_end_result(&mut self, end_result: SessionEndResultCode) {
        self.end_result = end_result;
    }

    pub fn get_signed_data(&self) -> &str {
        &self.signed_data
    }

    pub fn set_signed_data(&mut self, signed_data: String) {
        self.signed_data = signed_data;
    }

    pub fn get_value_in_base64(&self) -> String {
        self.value_in_base64.clone()
    }

    pub fn set_value_in_base64(&mut self, value_in_base64: String) {
        self.value_in_base64 = value_in_base64;
    }

    pub fn get_algorithm_name(&self) -> &str {
        self.algorithm_name.as_deref().unwrap_or("")
    }

    pub fn set_algorithm_name(&mut self, algorithm_name: String) {
        self.algorithm_name = Some(algorithm_name.clone());
    }

    pub fn get_certificate(&self) -> &str {
        self.certificate.as_str()
    }

    // pub fn get_parsed_certificate<'a>(&self) -> Result<X509Certificate<'a>, anyhow::Error> {
    //     let certificate = CertificateParser::get_der_certificate(self.certificate.clone()).unwrap();
    //     CertificateParser::parse_x509_certificate(certificate.as_slice())
    // }

    // pub fn get_certificate_instance(&self) -> Option<X509Certificate> {
    //     let certificate = CertificateParser::get_der_certificate(self.certificate.clone()).unwrap();
    //     let parsed = CertificateParser::parse_x509_certificate(certificate.as_slice()).unwrap();
    //     Some(parsed)
    // }

    pub fn set_certificate(&mut self, certificate: String) {
        self.certificate = certificate;
    }

    pub fn get_certificate_level(&self) -> &str {
        self.certificate_level.as_str()
    }

    pub fn set_certificate_level(&mut self, certificate_level: String) {
        self.certificate_level = certificate_level;
    }

    pub fn get_requested_certificate_level(&self) -> Option<&str> {
        self.requested_certificate_level.as_deref()
    }

    pub fn set_requested_certificate_level(&mut self, requested_certificate_level: Option<String>) {
        self.requested_certificate_level = requested_certificate_level;
    }

    pub fn get_value(&self) -> Result<Vec<u8>, Sma> {
        match self.value_in_base64.is_empty() {
            true => Err(TechnicalError(
                "No value in base64 format".to_string(),
            )),
            false => {
                let decoded =
                    general_purpose::STANDARD.decode(self.value_in_base64.as_str()).map_err(|_| {
                        TechnicalError(format!(
                            "Failed to decode base64: {}",
                            self.value_in_base64
                        ))
                    })?;
                Ok(decoded)
            }
        }
    }

    pub fn set_state(&mut self, state: SessionStatusCode) {
        self.state = state;
    }

    pub fn get_state(&self) -> SessionStatusCode {
        self.state.clone()
    }

    pub fn set_ignored_properties(&mut self, ignored_properties: Option<Vec<String>>) {
        self.ignored_properties = ignored_properties;
    }

    pub fn get_interaction_flow_used(&self) -> &str {
        self.interaction_flow_used.as_deref().unwrap_or("")
    }

    pub fn set_interaction_flow_used(&mut self, interaction_flow_used: Option<String>) {
        self.interaction_flow_used = interaction_flow_used;
    }

    pub fn is_running_state(&self) -> bool {
        self.state == SessionStatusCode::RUNNING
    }

    pub fn set_document_number(&mut self, document_number: Option<String>) {
        self.document_number = document_number;
    }

    pub fn get_document_number(&self) -> Option<&str> {
        self.document_number.as_deref()
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationIdentity {
    pub given_name: String,
    pub sur_name: String,
    pub identity_code: String,
    pub identity_number: String,
    pub country: String,
    pub auth_certificate: String,
    pub date_of_birth: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuthenticationIdentity {
    pub fn new() -> AuthenticationIdentity {
        AuthenticationIdentity {
            given_name: String::new(),
            sur_name: String::new(),
            identity_code: String::new(),
            identity_number: String::new(),
            country: String::new(),
            auth_certificate: String::new(),
            date_of_birth: None,
        }
    }

    pub fn set_given_name(&mut self, given_name: String) -> &mut AuthenticationIdentity {
        self.given_name = given_name;
        self
    }

    pub fn get_given_name(&self) -> &str {
        &self.given_name
    }

    pub fn set_sur_name(&mut self, sur_name: String) -> &mut AuthenticationIdentity {
        self.sur_name = sur_name;
        self
    }

    pub fn get_sur_name(&self) -> &str {
        &self.sur_name
    }

    pub fn set_identity_code(&mut self, identity_code: String) -> &mut AuthenticationIdentity {
        self.identity_code = identity_code;
        self
    }

    pub fn get_identity_code(&self) -> &str {
        &self.identity_code
    }

    pub fn set_identity_number(&mut self, identity_number: String) -> &mut AuthenticationIdentity {
        self.identity_number = identity_number;
        self
    }

    pub fn get_identity_number(&self) -> &str {
        &self.identity_number
    }

    pub fn set_country(&mut self, country: String) -> &mut AuthenticationIdentity {
        self.country = country;
        self
    }

    pub fn get_country(&self) -> &str {
        &self.country
    }

    pub fn set_auth_certificate(
        &mut self,
        auth_certificate: String,
    ) -> &mut AuthenticationIdentity {
        self.auth_certificate = auth_certificate;
        self
    }

    pub fn get_auth_certificate(&self) -> &str {
        &self.auth_certificate
    }

    pub fn set_date_of_birth(
        &mut self,
        date_of_birth: Option<chrono::DateTime<chrono::Utc>>,
    ) -> &mut AuthenticationIdentity {
        self.date_of_birth = date_of_birth;
        self
    }

    pub fn get_date_of_birth(&self) -> Option<&chrono::DateTime<chrono::Utc>> {
        self.date_of_birth.as_ref()
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartIdErrorResponse {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "title")]
    pub title: String,
    #[serde(rename = "status")]
    pub status: i32,
    #[serde(rename = "detail")]
    pub detail: String,
    #[serde(rename = "instance", skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(rename = "properties", skip_serializing_if = "Option::is_none")]
    pub properties: Option<String>,
    #[serde(rename = "code")]
    pub code: i32,
    #[serde(rename = "message")]
    pub message: String,
}

