use thiserror::Error;

#[derive(Error,Debug)]
pub enum MobileIdError {
    #[error("Mobile-ID error: {0}")]
    MidInternalError(String),
    #[error("Mobile-ID Unauthorised")]
    MidUnauthorized,
    #[error("Mobile-ID Service Unavailable")]
    MidServiceUnavailable,
    #[error("Missing or invalid parameter: {0}")]
    MissingOrInvalidParameter(String),
    #[error("Not a Mobile-ID client: {0}")]
    MidNotMidClient(String),
}