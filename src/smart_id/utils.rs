use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use crate::smart_id::errors::SmartIdError;
use crate::smart_id::errors::SmartIdError::UnprocessableSmartIdResponseException;
use std::fs::read_dir;

use anyhow::anyhow;
use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::PKey,
    sign::Verifier,
    stack::Stack,
    x509::{store::X509StoreBuilder, verify::X509VerifyFlags, X509StoreContext, X509},
};

use x509_certificate::X509Certificate;

use crate::smart_id::models::{AuthenticationIdentity, CertificateLevel, CertificateParser, SmartIdAuthenticationResponse, SmartIdAuthenticationResult, SmartIdAuthenticationResultError};
use x509_certificate::rfc5280::Certificate;

pub struct CertificateAttributes;

impl CertificateAttributes {
    pub fn get_date_of_birth_certificate_attribute(
        x509_certificate: &Certificate,
    ) -> Option<DateTime<Utc>> {
        let dob_as_string = Self::get_date_of_birth_from_certificate_field(x509_certificate)?;
        let timestamp = dob_as_string.parse::<i64>().ok()?;
        let naive_datetime = NaiveDateTime::from_timestamp_opt(timestamp, 0).unwrap();
        let datetime = DateTime::<Utc>::from_utc(naive_datetime, Utc);
        Some(datetime)
    }

    pub fn get_date_of_birth_from_certificate_field(cert: &Certificate) -> Option<String> {
        let extentions = cert.tbs_certificate.extensions.clone().unwrap();
        for entry in extentions.iter() {
            // OID for date of birth
            if entry.id.to_string() == "1.3.6.1.5.5.7.9.1".to_string() {
                return Some(String::from_utf8(entry.value.as_slice().unwrap().to_vec()).unwrap());
            }
        }
        None
    }
}

pub struct NationalIdentityNumber;

impl NationalIdentityNumber {
    pub fn get_date_of_birth(
        authentication_identity: &AuthenticationIdentity,
    ) -> Result<Option<DateTime<Utc>>, SmartIdError> {
        let identity_number = authentication_identity.to_owned().identity_code;
        match authentication_identity
            .country
            .to_uppercase()
            .as_str()
        {
            "EE" | "LT" => Self::parse_ee_lt_date_of_birth(identity_number),
            "LV" => Self::parse_lv_date_of_birth(identity_number),
            _ => Err(UnprocessableSmartIdResponseException(format!(
                "Unknown country: {}",
                authentication_identity.country
            ))),
        }
    }

    fn parse_ee_lt_date_of_birth(
        ee_or_lt_national_identity_number: String,
    ) -> Result<Option<DateTime<Utc>>, SmartIdError> {
        let id_no: Vec<&str>= ee_or_lt_national_identity_number.split('-').collect();
        let birth_day = &id_no[1][5..7];
        let birth_month = &id_no[1][3..5];
        let birth_year_two_digit = &id_no[1][1..3];
        let birth_year_four_digit = match &id_no[1][..1] {
            "1" | "2" => format!("18{}", birth_year_two_digit),
            "3" | "4" => format!("19{}", birth_year_two_digit),
            "5" | "6" => format!("20{}", birth_year_two_digit),
            _ => {
                return Err(UnprocessableSmartIdResponseException(format!(
                    "Invalid personal code {}",
                    ee_or_lt_national_identity_number
                )));
            }
        };

        let date = Self::naive_date(birth_year_four_digit, birth_month, birth_day);

        let datetime =
            Utc.from_utc_datetime(&date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap()));
        Ok(Some(datetime))
    }

    fn parse_lv_date_of_birth(
        lv_national_identity_number: String,
    ) -> Result<Option<DateTime<Utc>>, SmartIdError> {
        let birth_day = &lv_national_identity_number[0..2];
        if birth_day == "32" {
            return Ok(None);
        }

        let birth_month = &lv_national_identity_number[2..4];
        let birth_year_two_digit = &lv_national_identity_number[4..6];
        let century = &lv_national_identity_number[7..8];
        let birth_year_four_digit = match century {
            "0" => format!("18{}", birth_year_two_digit),
            "1" => format!("19{}", birth_year_two_digit),
            "2" => format!("20{}", birth_year_two_digit),
            _ => {
                return Err(UnprocessableSmartIdResponseException(format!(
                    "Invalid personal code: {}",
                    lv_national_identity_number
                )));
            }
        };

        let date = Self::naive_date(birth_year_four_digit, birth_month, birth_day);
        let datetime =
            Utc.from_utc_datetime(&date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap()));
        Ok(Some(datetime))
    }

    fn naive_date(birth_year_four_digit: String, birth_month: &str, birth_day: &str) -> NaiveDate {
        NaiveDate::from_ymd_opt(
            birth_year_four_digit.parse::<i32>().unwrap(),
            birth_month.parse::<u32>().unwrap(),
            birth_day.parse::<u32>().unwrap(),
        )
        .unwrap()
    }
}


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
        requested_cert_level: CertificateLevel,
        received_cert_level: CertificateLevel,
        certificate: X509Certificate,
    ) -> Result<SmartIdAuthenticationResult, ErrorStack> {
        // self.validate_authentication_response(authentication_response)
        //     .unwrap();

        let mut authentication_result = SmartIdAuthenticationResult::new();
        let identity = self.construct_authentication_identity(
            certificate.as_ref(),
        )?;
        authentication_result.set_authentication_identity(identity);

        // if !self.verify_response_end_result(authentication_response) {
        //     authentication_result.set_valid(false);
        //     authentication_result.add_error(SmartIdAuthenticationResultError::InvalidEndResult);
        // }
        // if !self.verify_signature(certificate)? {
        //     authentication_result.set_valid(false);
        //     authentication_result
        //         .add_error(SmartIdAuthenticationResultError::SignatureVerificationFailure);
        // }
        if !self.verify_certificate_expiry(certificate.as_ref()) {
            authentication_result.set_valid(false);
            authentication_result.add_error(SmartIdAuthenticationResultError::CertificateExpired);
        }
        // if !self.is_certificate_trusted(certificate.encode_pem().unwrap().into_bytes())? {
        //     authentication_result.set_valid(false);
        //     authentication_result
        //         .add_error(SmartIdAuthenticationResultError::CertificateNotTrusted);
        // }
        if !self.verify_certificate_level(received_cert_level,requested_cert_level) {
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

    fn verify_signature(
        &self,
        x509_cert_string: String,
        signed_data: String,
        signature: String,
    ) -> Result<bool, ErrorStack> {
        let prepared_certificate =
            CertificateParser::get_der_certificate(x509_cert_string)
                .unwrap();
        let public_key = PKey::public_key_from_pem(prepared_certificate.as_slice()).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key).unwrap();
        verifier
            .update(signed_data.as_bytes())
            .unwrap();
        Ok(verifier.verify(signature.as_bytes()).unwrap())
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
        received_cert_level: CertificateLevel,
        requested_cert_level: CertificateLevel,
    ) -> bool {
        received_cert_level.is_equal_or_above(requested_cert_level)
    }

    fn construct_authentication_identity(
        &self,
        certificate: &Certificate,
    ) -> Result<AuthenticationIdentity, ErrorStack> {
        let mut identity = AuthenticationIdentity{
            given_name: "".to_string(),
            sur_name: "".to_string(),
            identity_code: "".to_string(),
            identity_number: "".to_string(),
            country: "".to_string(),
            auth_certificate: certificate.to_owned(),
            date_of_birth: None,
        };
        let tbs_certificate = &certificate.tbs_certificate;
        let subject = &tbs_certificate.subject;

        // Extract the given name
        if let Some(given_name) = subject.iter_by_oid("2.5.4.42".parse().unwrap()).next() {
            identity.given_name = given_name.value.to_string().unwrap();
        }

        // Extract the surname
        if let Some(surname) = subject.iter_by_oid("2.5.4.4".parse().unwrap()).next() {
            identity.sur_name = surname.value.to_string().unwrap();
        }

        // Extract the identity code
        if let Some(identity_code) = subject.iter_by_oid("2.5.4.5".parse().unwrap()).next() {
            let identity_code = identity_code.value.to_string().unwrap();
            identity.identity_code =identity_code.to_owned();
            let identity_number = identity_code.splitn(2, '-').nth(1);
            identity.identity_number = identity_number.unwrap().to_string();
        }

        // Extract the country
        if let Some(country) = subject.iter_country().next() {
            identity.country = country.value.to_string().unwrap();
        }

        identity.date_of_birth = Self::get_date_of_birth(&identity)?;
        Ok(identity)
    }

    fn initialize_trusted_ca_certificates_from_resources(
        resources_location: &str,
    ) -> Result<Vec<String>, ErrorStack> {
        let mut trusted_ca_certificates = Vec::new();
        // let trusted_certificates_directory = format!("{}/trusted_certificates", resources_location);
        // for entry in read_dir(trusted_certificates_directory).unwrap() {
        //     if let Ok(file) = entry {
        //         let path = file.path();
        //         if !path.is_dir() && !file.file_name().to_string_lossy().starts_with(".") {
        //             trusted_ca_certificates.push(path.to_string_lossy().into_owned());
        //         }
        //     }
        // }

        Ok(trusted_ca_certificates)
    }

    fn is_certificate_trusted(&self, certificate_as_pem: Vec<u8>) -> Result<bool, ErrorStack> {
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
        let date_of_birth_from_certificate_field =
            CertificateAttributes::get_date_of_birth_certificate_attribute(
                &identity.auth_certificate,
            );
        if let Some(date_of_birth) = date_of_birth_from_certificate_field {
            return Ok(Some(date_of_birth));
        }
        let date_of_birth = NationalIdentityNumber::get_date_of_birth(&identity).unwrap();
        Ok(date_of_birth)
    }
}

