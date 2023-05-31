

/// IDCardClient is a client for the IDCard service
pub struct IDCardClient {
}

impl IDCardClient {
    /// Create a new IDCardClient
    pub fn new() -> Self {
        Self {
        }
    }
}

#[derive(Debug,thiserror::Error)]
pub enum IDCardError {
    #[error("Not implemented")]
    NotImplemented,
}