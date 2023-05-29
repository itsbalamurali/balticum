use chrono::{DateTime, NaiveDateTime, Utc};
use x509_parser::parse_x509_certificate;

pub struct CertificateAttributes;

impl CertificateAttributes {
    pub fn new() -> CertificateAttributes {
        CertificateAttributes {}
    }
    pub fn get_date_of_birth_certificate_attribute(
        &self,
        x509_certificate: &str,
    ) -> Option<DateTime<Utc>> {
        let dob_as_string = self.get_date_of_birth_from_certificate_field(x509_certificate)?;
        let timestamp = dob_as_string.parse::<i64>().ok()?;
        let naive_datetime = NaiveDateTime::from_timestamp_opt(timestamp, 0).unwrap();
        let datetime = DateTime::<Utc>::from_utc(naive_datetime, Utc);
        Some(datetime)
    }

    pub fn get_date_of_birth_from_certificate_field(&self, cert_as_string: &str) -> Option<String> {
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
