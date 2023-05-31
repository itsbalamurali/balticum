use thiserror::Error;

#[derive(Error, Debug)]
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
    #[error("Limit exceeded")]
    MidLimitExceeded,
    #[error("Forbidden!")]
    MidForbidden,
    #[error("System is under maintenance, retry later")]
    MidSystemUnderMaintenance,
    #[error("The client is old and not supported any more. Relying Party must contact customer support.")]
    MidClientOld,
    #[error("Person should view app or self-service portal now.")]
    MidPersonShouldViewAppOrSelfServicePortalNow,
    #[error("No suitable account of requested type found, but user has some other accounts.")]
    MidNoSuitableAccountFound,
    #[error("Session timeout reached. User has to start authentication process again.")]
    MidSessionTimeout,
    #[error("User cancelled the session from his/her mobile phone.")]
    MidUserCancelled,
    #[error("Phone is unreachable.")]
    MidPhoneAbsent,
    #[error("Hash does not match with the certificate type.")]
    MidSignatureHashMismatch,
    #[error("SMS sending or SIM error.")]
    MidSimError,
}