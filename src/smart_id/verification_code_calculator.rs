use sha2::{Digest, Sha256};

pub struct VerificationCodeCalculator;

impl VerificationCodeCalculator {
    pub fn calculate(document_hash: &str) -> String {
        let digest = Self::calculate_digest(document_hash);
        let two_rightmost_bytes = &digest[digest.len() - 2..];
        let positive_integer = u16::from_be_bytes([two_rightmost_bytes[0], two_rightmost_bytes[1]]);
        let verification_code = (positive_integer % 10_000).to_string();
        format!("{:04}", verification_code)
    }

    fn calculate_digest(document_hash: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(document_hash);
        hasher.finalize().into()
    }
}
