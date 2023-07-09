use x509_parser::parse_x509_certificate;
use chrono::{DateTime, NaiveDate,NaiveDateTime, NaiveTime, TimeZone, Utc};

use crate::smart_id::errors::SmartIdError;
use crate::smart_id::errors::SmartIdError::UnprocessableSmartIdResponseException;
use crate::smart_id::models::AuthenticationIdentity;

pub struct CertificateAttributes;

impl CertificateAttributes {
    pub fn get_date_of_birth_certificate_attribute(
        x509_certificate: &str,
    ) -> Option<DateTime<Utc>> {
        let dob_as_string = Self::get_date_of_birth_from_certificate_field(x509_certificate)?;
        let timestamp = dob_as_string.parse::<i64>().ok()?;
        let naive_datetime = NaiveDateTime::from_timestamp_opt(timestamp, 0).unwrap();
        let datetime = DateTime::<Utc>::from_utc(naive_datetime, Utc);
        Some(datetime)
    }

    pub fn get_date_of_birth_from_certificate_field(cert_as_string: &str) -> Option<String> {
        let cert = match parse_x509_certificate(cert_as_string.as_bytes()) {
            Ok((_, cert)) => cert,
            Err(_) => return None,
        };

        for entry in cert.tbs_certificate.extensions() {
            // OID for date of birth
            if entry.oid.to_string() == "1.3.6.1.5.5.7.9.1".to_string() {
                return Some(String::from_utf8_lossy(entry.value).parse().unwrap());
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
        let identity_number = authentication_identity.get_identity_code();
        match authentication_identity
            .get_country()
            .to_uppercase()
            .as_str()
        {
            "EE" | "LT" => Self::parse_ee_lt_date_of_birth(identity_number),
            "LV" => Self::parse_lv_date_of_birth(identity_number),
            _ => Err(UnprocessableSmartIdResponseException(format!(
                "Unknown country: {}",
                authentication_identity.get_country()
            ))),
        }
    }

    fn parse_ee_lt_date_of_birth(
        ee_or_lt_national_identity_number: &str,
    ) -> Result<Option<DateTime<Utc>>, SmartIdError> {
        let birth_day = &ee_or_lt_national_identity_number[5..7];
        let birth_month = &ee_or_lt_national_identity_number[3..5];
        let birth_year_two_digit = &ee_or_lt_national_identity_number[1..3];
        let birth_year_four_digit = match &ee_or_lt_national_identity_number[..1] {
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

        let date = Self::naive_date(
            birth_year_four_digit,
            birth_month,
            birth_day,
        );

        let datetime =
            Utc.from_utc_datetime(&date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap()));
        Ok(Some(datetime))
    }

    fn parse_lv_date_of_birth(
        lv_national_identity_number: &str,
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

        let date = Self::naive_date(
            birth_year_four_digit,
            birth_month,
            birth_day,
        );
        let datetime =
            Utc.from_utc_datetime(&date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap()));
        Ok(Some(datetime))
    }

    fn naive_date(birth_year_four_digit: String, birth_month:&str, birth_day:&str) -> NaiveDate {
        NaiveDate::from_ymd_opt(
            birth_year_four_digit.parse::<i32>().unwrap(),
            birth_month.parse::<u32>().unwrap(),
            birth_day.parse::<u32>().unwrap(),
        )
            .unwrap()
    }
}
