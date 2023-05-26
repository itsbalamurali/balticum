use std::{
    fs::{
        read_dir
    },
    time::SystemTime
};
use anyhow::anyhow;
use chrono::{DateTime, Local, Utc};
use openssl::{
    x509::{
        X509,
        X509StoreContext,
        store::{X509StoreBuilder},
        verify::X509VerifyFlags
    },
    stack::Stack,
    hash::MessageDigest,
    sign::Verifier,
    pkey::PKey,
    error::ErrorStack,
};
use crate::smart_id::certificate_level::CertificateLevel;
use crate::smart_id::models::authentication_identity::AuthenticationIdentity;
use crate::smart_id::models::{AuthenticationCertificate, CertificateParser, SessionEndResultCode, SmartIdAuthenticationResponse, SmartIdAuthenticationResult, SmartIdAuthenticationResultError};
use crate::smart_id::utils::certificate_attributes::CertificateAttributes;
use crate::smart_id::utils::national_identity_number::NationalIdentityNumber;

pub struct AuthenticationResponseValidator {
    trusted_ca_certificates: Vec<String>,
}

impl AuthenticationResponseValidator {
    pub fn new(resources_location: Option<&str>) -> Result<Self, ErrorStack> {
        let resources_location = match resources_location {
            Some(location) => location.to_owned(),
            None => format!("{}/../../../resources", env!("CARGO_MANIFEST_DIR")),
        };

        let trusted_ca_certificates = Self::initialize_trusted_ca_certificates_from_resources(&resources_location)?;
        Ok(Self {
            trusted_ca_certificates,
        })
    }

    pub fn validate(&self, authentication_response: &SmartIdAuthenticationResponse) -> Result<SmartIdAuthenticationResult, ErrorStack> {
        self.validate_authentication_response(authentication_response).unwrap();

        let mut authentication_result = SmartIdAuthenticationResult::new();
        let identity = self.construct_authentication_identity(&authentication_response.certificate_instance, &authentication_response.certificate)?;
        authentication_result.set_authentication_identity(identity);

        if !self.verify_response_end_result(authentication_response) {
            authentication_result.set_valid(false);
            authentication_result.add_error(SmartIdAuthenticationResultError::InvalidEndResult);
        }
        if !self.verify_signature(authentication_response)? {
            authentication_result.set_valid(false);
            authentication_result.add_error(SmartIdAuthenticationResultError::SignatureVerificationFailure);
        }
        if !self.verify_certificate_expiry(&authentication_response.certificate_instance)? {
            authentication_result.set_valid(false);
            authentication_result.add_error(SmartIdAuthenticationResultError::CertificateExpired);
        }
        if !self.is_certificate_trusted(&authentication_response.certificate)? {
            authentication_result.set_valid(false);
            authentication_result.add_error(SmartIdAuthenticationResultError::CertificateNotTrusted);
        }
        if !self.verify_certificate_level(authentication_response) {
            authentication_result.set_valid(false);
            authentication_result.add_error(SmartIdAuthenticationResultError::CertificateLevelMismatch);
        }

        Ok(authentication_result)
    }

    fn validate_authentication_response(&self, authentication_response: &SmartIdAuthenticationResponse) -> Result<(), anyhow::Error> {
        if authentication_response.certificate.is_empty() {
            return Err(anyhow!("Certificate is not present in the authentication response"));
        }
        if authentication_response.value_in_base64.is_empty() {
            return Err(anyhow!("Signature is not present in the authentication response"));
        }
        if authentication_response.signed_data.is_empty() {
            return Err(anyhow!("Signable data is not present in the authentication response"));
        }
        Ok(())
    }

    fn verify_response_end_result(&self, authentication_response: &SmartIdAuthenticationResponse) -> bool {
        authentication_response.end_result == SessionEndResultCode::OK
    }

    fn verify_signature(&self, authentication_response: &SmartIdAuthenticationResponse) -> Result<bool, ErrorStack> {
        let prepared_certificate = CertificateParser::get_pem_certificate(&authentication_response.certificate).unwrap();
        let signature = authentication_response.value.clone();
        let public_key = PKey::public_key_from_pem(prepared_certificate.as_bytes())?;

        let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key)?;
        verifier.update(authentication_response.signed_data.as_bytes())?;
        Ok(verifier.verify(signature.as_bytes())?)
    }

    fn verify_certificate_expiry(&self, authentication_certificate: &AuthenticationCertificate) -> Result<bool, ErrorStack> {
        let valid_to = &authentication_certificate.valid_to;
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        Ok(valid_to > &now.as_secs())
    }

    fn verify_certificate_level(&self, authentication_response: &SmartIdAuthenticationResponse) -> bool {
        let cert_level = CertificateLevel::new(&authentication_response.certificate_level);
        let requested_certificate_level = &authentication_response.requested_certificate_level.unwrap();
        requested_certificate_level.is_empty() || cert_level.is_equal_or_above(requested_certificate_level)
    }

    fn construct_authentication_identity(&self, certificate: &AuthenticationCertificate, x509_certificate: &str) -> Result<AuthenticationIdentity, ErrorStack> {
        let mut identity = AuthenticationIdentity::new();
        identity.set_auth_certificate(x509_certificate.to_owned());

        let subject = &certificate.subject;
        let given_name = subject.gn.clone();
            identity.set_given_name(given_name);
        let surname = subject.sn.clone();
            identity.set_sur_name(surname);

        let serial_number = subject.serial_number.clone();
            identity.set_identity_code(serial_number.clone());
            let identity_number = serial_number.splitn(2, '-').nth(1).unwrap();
            identity.set_identity_number(identity_number.to_owned());

        let country = subject.c.clone();
            identity.set_country(country);

        identity.set_date_of_birth(Self::get_date_of_birth(&identity)?);

        Ok(identity)
    }

    fn initialize_trusted_ca_certificates_from_resources(resources_location: &str) -> Result<Vec<String>, ErrorStack> {
        let mut trusted_ca_certificates = Vec::new();
        let trusted_certificates_directory = format!("{}/trusted_certificates", resources_location);
        for entry in read_dir(trusted_certificates_directory).unwrap() {
            if let Ok(file) = entry {
                let path = file.path();
                if !path.is_dir() && !file.file_name().to_string_lossy().starts_with(".") {
                    trusted_ca_certificates.push(path.to_string_lossy().into_owned());
                }
            }
        }

        Ok(trusted_ca_certificates)
    }

    fn is_certificate_trusted(&self, certificate: &str) -> Result<bool, ErrorStack> {
        let certificate_as_pem = CertificateParser::get_pem_certificate(certificate).unwrap();
        let x509 = X509::from_pem(certificate_as_pem.as_bytes()).unwrap();
        let mut store = X509StoreBuilder::new().unwrap();
        for ca_certificate in &self.trusted_ca_certificates {
            let ca_certificate_pem = std::fs::read_to_string(ca_certificate).unwrap();
            let ca_x509 = X509::from_pem(ca_certificate_pem.as_bytes()).unwrap();
            store.add_cert(ca_x509)?;
        }
        store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        let mut store_ctx = X509StoreContext::new()?;
        store_ctx.init(&store.build(), &x509, &Stack::new().unwrap(),|c| c.verify_cert())?;
        Ok(store_ctx.verify_cert()?)
    }

    fn get_date_of_birth(identity: &AuthenticationIdentity) -> Result<Option<DateTime<Utc>>, ErrorStack> {
        let certificate_attribute_util = CertificateAttributes::new();
        let date_of_birth_from_certificate_field = certificate_attribute_util.get_date_of_birth_certificate_attribute(&identity.auth_certificate);
        if let Some(date_of_birth) = date_of_birth_from_certificate_field {
            return Ok(Some(date_of_birth));
        }

        let national_identity_number_util = NationalIdentityNumber::new();
        let date_of_birth = national_identity_number_util.get_date_of_birth(&identity).unwrap();
        Ok(date_of_birth)
    }
}
