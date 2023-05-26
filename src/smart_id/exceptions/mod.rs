use thiserror::Error;

#[derive(Error, Debug)]
pub enum Exception {
    #[error("User selected wrong verification code")]
    UserSelectedWrongVerificationCodeException,

    #[error("Document unusable")]
    DocumentUnusableException,

    #[error("Invalid response from Smart-ID: {0}")]
    UnprocessableSmartIdResponseException(String),

    #[error("Required interaction not supported by app")]
    RequiredInteractionNotSupportedByAppException,

    #[error("Session timed out")]
    SessionTimeoutException,

    #[error("Technical error {0}")]
    TechnicalErrorException(String),

    #[error("User refused certificate choice")]
    UserRefusedCertChoiceException,

    #[error("User refused confirmation message with VC choice")]
    UserRefusedConfirmationMessageWithVcChoiceException,

    #[error("User refused VC choice")]
    UserRefusedVcChoiceException,

    #[error("User refused")]
    UserRefusedException,

    #[error("User refused display text and PIN")]
    UserRefusedDisplayTextAndPinException,

    #[error("User refused confirmation message")]
    UserRefusedConfirmationMessageException,

    #[error("Session not found")]
    SessionNotFoundException,

    #[error("Invalid parameters: {0}")]
    InvalidParametersException(String),
}
