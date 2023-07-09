use std::fs::read_dir;
use std::str::FromStr;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::PKey,
    sign::Verifier,
    stack::Stack,
    x509::{store::X509StoreBuilder, verify::X509VerifyFlags, X509StoreContext, X509},
};
use x509_certificate::asn1time::{Time, UtcTime};
use x509_certificate::rfc5280::Certificate;
use x509_certificate::X509Certificate;

use crate::smart_id::models::{
    AuthenticationIdentity, CertificateLevel, CertificateParser, SessionEndResultCode,
    SmartIdAuthenticationResponse, SmartIdAuthenticationResult, SmartIdAuthenticationResultError,
};
use crate::smart_id::utils::CertificateAttributes;
use crate::smart_id::utils::NationalIdentityNumber;

pub struct AuthenticationResponseValidator {
    trusted_ca_certificates: Vec<String>,
}

impl AuthenticationResponseValidator {
    pub fn new(resources_location: Option<&str>) -> Result<Self, ErrorStack> {
        let resources_location = match resources_location {
            Some(location) => location.to_owned(),
            None => format!("{}/../../../resources", env!("CARGO_MANIFEST_DIR")),
        };

        let trusted_ca_certificates =
            Self::initialize_trusted_ca_certificates_from_resources(&resources_location)?;
        Ok(Self {
            trusted_ca_certificates,
        })
    }

    pub fn validate(
        &self,
        authentication_response: &SmartIdAuthenticationResponse,
    ) -> Result<SmartIdAuthenticationResult, ErrorStack> {
        self.validate_authentication_response(authentication_response)
            .unwrap();

        let certificate= X509Certificate::from_der(&authentication_response.certificate.as_bytes()).unwrap();
        let mut authentication_result = SmartIdAuthenticationResult::new();
        let identity = self.construct_authentication_identity(
            certificate.as_ref(),
            &authentication_response.certificate,
        )?;
        authentication_result.set_authentication_identity(identity);

        if !self.verify_response_end_result(authentication_response) {
            authentication_result.set_valid(false);
            authentication_result.add_error(SmartIdAuthenticationResultError::InvalidEndResult);
        }
        if !self.verify_signature(authentication_response)? {
            authentication_result.set_valid(false);
            authentication_result
                .add_error(SmartIdAuthenticationResultError::SignatureVerificationFailure);
        }
        if !self.verify_certificate_expiry(certificate.as_ref()) {
            authentication_result.set_valid(false);
            authentication_result.add_error(SmartIdAuthenticationResultError::CertificateExpired);
        }
        if !self.is_certificate_trusted(authentication_response.to_owned().certificate)? {
            authentication_result.set_valid(false);
            authentication_result
                .add_error(SmartIdAuthenticationResultError::CertificateNotTrusted);
        }
        if !self.verify_certificate_level(authentication_response) {
            authentication_result.set_valid(false);
            authentication_result
                .add_error(SmartIdAuthenticationResultError::CertificateLevelMismatch);
        }

        Ok(authentication_result)
    }

    fn validate_authentication_response(
        &self,
        authentication_response: &SmartIdAuthenticationResponse,
    ) -> Result<(), anyhow::Error> {
        if authentication_response.certificate.is_empty() {
            return Err(anyhow!(
                "Certificate is not present in the authentication response"
            ));
        }
        if authentication_response.value_in_base64.is_empty() {
            return Err(anyhow!(
                "Signature is not present in the authentication response"
            ));
        }
        if authentication_response.signed_data.is_empty() {
            return Err(anyhow!(
                "Signable data is not present in the authentication response"
            ));
        }
        Ok(())
    }

    fn verify_response_end_result(
        &self,
        authentication_response: &SmartIdAuthenticationResponse,
    ) -> bool {
        authentication_response.end_result == SessionEndResultCode::Ok
    }

    fn verify_signature(
        &self,
        authentication_response: &SmartIdAuthenticationResponse,
    ) -> Result<bool, ErrorStack> {
        let prepared_certificate =
            CertificateParser::get_der_certificate(authentication_response.certificate.clone())
                .unwrap();
        let signature = authentication_response.get_value().unwrap();
        let public_key = PKey::public_key_from_pem(prepared_certificate.as_slice()).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key).unwrap();
        verifier
            .update(authentication_response.signed_data.as_bytes())
            .unwrap();
        Ok(verifier.verify(signature.as_slice()).unwrap())
    }

    // TODO: Fix this
     fn verify_certificate_expiry(&self, authentication_certificate: &Certificate) -> bool {
    //     let valid_to = authentication_certificate.tbs_certificate.validity.not_after.to_owned();
    //     let now = Time::UtcTime(UtcTime::now());
    //     valid_to > now
    false
    }

    fn verify_certificate_level(
        &self,
        authentication_response: &SmartIdAuthenticationResponse,
    ) -> bool {
        let cert_level =
            CertificateLevel::from_str(&authentication_response.to_owned().certificate_level)
                .unwrap();
        let requested_certificate_level = &authentication_response
            .requested_certificate_level
            .as_ref()
            .unwrap();
        requested_certificate_level.is_empty()
            || cert_level.is_equal_or_above(requested_certificate_level.as_str())
    }

    fn construct_authentication_identity(
        &self,
        certificate: &Certificate,
        x509_certificate: &str,
    ) -> Result<AuthenticationIdentity, ErrorStack> {
        let mut identity = AuthenticationIdentity::new();
        identity.set_auth_certificate(x509_certificate.to_owned());
        let tbs_certificate = &certificate.tbs_certificate;
        let subject = &tbs_certificate.subject;

        // Extract the given name
        if let Some(given_name) = subject.iter_by_oid("2.5.4.42".parse().unwrap()).next() {
            identity
                .set_given_name(given_name.value.to_string().unwrap());
        }

        // Extract the surname
        if let Some(surname) = subject.iter_by_oid("2.5.4.4".parse().unwrap()).next() {
            identity.set_sur_name(surname.value.to_string().unwrap());
        }

        // Extract the identity code
        if let Some(identity_code) = subject.iter_by_oid("2.5.4.5".parse().unwrap()).next() {
            let identity_code = identity_code.value.to_string().unwrap();
            identity.set_identity_code(identity_code.to_owned());
            let identity_number = identity_code.splitn(2, '-').nth(1);
            identity.set_identity_number(identity_number.unwrap().to_string());
        }

        // Extract the country
        if let Some(country) = subject.iter_country().next() {
            identity.set_country(country.value.to_string().unwrap());
        }

        identity.set_date_of_birth(Self::get_date_of_birth(&identity)?);

        Ok(identity)
    }

    fn initialize_trusted_ca_certificates_from_resources(
        resources_location: &str,
    ) -> Result<Vec<String>, ErrorStack> {
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

    fn is_certificate_trusted(&self, certificate: String) -> Result<bool, ErrorStack> {
        let certificate_as_pem = CertificateParser::get_der_certificate(certificate).unwrap();
        let x509 = X509::from_pem(certificate_as_pem.as_slice()).unwrap();
        let mut store = X509StoreBuilder::new().unwrap();
        for ca_certificate in &self.trusted_ca_certificates {
            let ca_certificate_pem = std::fs::read_to_string(ca_certificate).unwrap();
            let ca_x509 = X509::from_pem(ca_certificate_pem.as_bytes()).unwrap();
            store.add_cert(ca_x509)?;
        }
        store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
        let mut store_ctx = X509StoreContext::new()?;
        store_ctx.init(&store.build(), &x509, &Stack::new().unwrap(), |c| {
            c.verify_cert()
        })?;
        Ok(store_ctx.verify_cert()?)
    }

    fn get_date_of_birth(
        identity: &AuthenticationIdentity,
    ) -> Result<Option<DateTime<Utc>>, ErrorStack> {
        let date_of_birth_from_certificate_field = CertificateAttributes
            ::get_date_of_birth_certificate_attribute(&identity.auth_certificate);
        if let Some(date_of_birth) = date_of_birth_from_certificate_field {
            return Ok(Some(date_of_birth));
        }
        let date_of_birth = NationalIdentityNumber::
            get_date_of_birth(&identity)
            .unwrap();
        Ok(date_of_birth)
    }
}
