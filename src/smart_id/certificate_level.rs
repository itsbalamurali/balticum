use strum::{Display, EnumString};
pub struct CertificateLevel {
    certificate_level: CertificateLevelCode,
}

impl CertificateLevel {
    pub fn new(certificate_level: &str) -> Self {
        Self {
            certificate_level: certificate_level.to_owned().parse().unwrap(),
        }
    }

    pub fn is_equal_or_above(&self, certificate_level: &str) -> bool {
        if self.certificate_level == certificate_level.parse().unwrap() {
            true
        } else {
            match (certificate_level.parse().unwrap(), &self.certificate_level) {
                (CertificateLevelCode::ADVANCED, CertificateLevelCode::ADVANCED)
                | (CertificateLevelCode::QUALIFIED, CertificateLevelCode::QUALIFIED)
                | (CertificateLevelCode::QUALIFIED, CertificateLevelCode::ADVANCED) => true,
                _ => false,
            }
        }
    }
}

#[derive(Display,Copy, Clone,EnumString,PartialEq)]
enum CertificateLevelCode {
    ADVANCED,
    QUALIFIED,
}
