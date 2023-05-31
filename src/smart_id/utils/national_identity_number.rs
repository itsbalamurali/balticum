use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc};

use crate::smart_id::errors::Sma;
use crate::smart_id::errors::Sma::UnprocessableSmartIdResponseException;
use crate::smart_id::models::AuthenticationIdentity;

pub struct NationalIdentityNumber;

impl NationalIdentityNumber {
    pub fn new() -> NationalIdentityNumber {
        NationalIdentityNumber {}
    }

    pub fn get_date_of_birth(
        &self,
        authentication_identity: &AuthenticationIdentity,
    ) -> Result<Option<DateTime<Utc>>, Sma> {
        let identity_number = authentication_identity.get_identity_code();
        match authentication_identity
            .get_country()
            .to_uppercase()
            .as_str()
        {
            "EE" | "LT" => self.parse_ee_lt_date_of_birth(identity_number),
            "LV" => self.parse_lv_date_of_birth(identity_number),
            _ => Err(UnprocessableSmartIdResponseException(format!(
                "Unknown country: {}",
                authentication_identity.get_country()
            ))),
        }
    }

    fn parse_ee_lt_date_of_birth(
        &self,
        ee_or_lt_national_identity_number: &str,
    ) -> Result<Option<DateTime<Utc>>, Sma> {
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

        let date = NaiveDate::from_ymd_opt(
            birth_year_four_digit.parse::<i32>().unwrap(),
            birth_month.parse::<u32>().unwrap(),
            birth_day.parse::<u32>().unwrap(),
        )
            .unwrap();
        let datetime =
            Utc.from_utc_datetime(&date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap()));
        Ok(Some(datetime))
    }

    fn parse_lv_date_of_birth(
        &self,
        lv_national_identity_number: &str,
    ) -> Result<Option<DateTime<Utc>>, Sma> {
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

        let date = NaiveDate::from_ymd_opt(
            birth_year_four_digit.parse::<i32>().unwrap(),
            birth_month.parse::<u32>().unwrap(),
            birth_day.parse::<u32>().unwrap(),
        )
            .unwrap();
        let datetime =
            Utc.from_utc_datetime(&date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap()));
        Ok(Some(datetime))
    }
}
