use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Cryptography error: {0}")]
    Cryptography(String),

    #[error("Pool error: {0}")]
    Pool(#[from] diesel::ConnectionError),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account is inactive")]
    AccountInactive,

    #[error("Email already exists")]
    EmailExists,

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("MFA required")]
    MfaRequired {
        mfa_type: String,
        session_token: String,
    },

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("MFA not configured")]
    MfaNotConfigured,

    #[error("Invalid OTP code")]
    InvalidOtp,

    #[error("OTP expired")]
    OtpExpired,

    #[error("Email already verified")]
    EmailAlreadyVerified,

    #[error("Invalid recovery code")]
    InvalidRecoveryCode,

    #[error("Role not found: {0}")]
    RoleNotFound(String),

    #[error("Invalid user ID format")]
    InvalidUserId,

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("TOTP already enabled")]
    TotpAlreadyEnabled,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Internal error")]
    Internal,
}

impl AuthError {
    pub fn to_status(&self) -> tonic::Status {
        use tonic::{Code, Status};

        match self {
            Self::Database(_) => Status::new(Code::Internal, "Internal server error"),
            Self::Configuration(_) => Status::new(Code::Internal, "Internal server error"),
            Self::Cryptography(_) => Status::new(Code::Internal, "Internal server error"),
            Self::InvalidCredentials => Status::new(Code::Unauthenticated, self.to_string()),
            Self::AccountInactive => Status::new(Code::PermissionDenied, self.to_string()),
            Self::EmailExists => Status::new(Code::AlreadyExists, self.to_string()),
            Self::UserNotFound => Status::new(Code::NotFound, self.to_string()),
            Self::InvalidToken => Status::new(Code::Unauthenticated, self.to_string()),
            Self::TokenExpired => Status::new(Code::Unauthenticated, "Token expired"),
            Self::MfaRequired { .. } => Status::new(Code::Unauthenticated, "MFA required"),
            Self::InvalidMfaCode => Status::new(Code::Unauthenticated, self.to_string()),
            Self::MfaNotConfigured => Status::new(Code::FailedPrecondition, self.to_string()),
            Self::Pool(_) => Status::new(Code::Internal, "Internal server error"),
            Self::InvalidOtp => Status::new(Code::Unauthenticated, self.to_string()),
            Self::OtpExpired => Status::new(Code::DeadlineExceeded, "OTP code expired"),
            Self::EmailAlreadyVerified => Status::new(Code::FailedPrecondition, self.to_string()),
            Self::InvalidRecoveryCode => Status::new(Code::Unauthenticated, self.to_string()),
            Self::RoleNotFound(_) => Status::new(Code::NotFound, self.to_string()),
            Self::InvalidUserId => Status::new(Code::InvalidArgument, self.to_string()),
            Self::InvalidInput(_) => Status::new(Code::InvalidArgument, self.to_string()),
            Self::TotpAlreadyEnabled => Status::new(Code::AlreadyExists, self.to_string()),
            Self::EmailNotVerified => Status::new(Code::Unauthenticated, self.to_string()),
            Self::Internal => Status::new(Code::Internal, "Internal server error"),
        }
    }
}

impl From<AuthError> for tonic::Status {
    fn from(err: AuthError) -> Self {
        err.to_status()
    }
}


pub type AuthResult<T> = Result<T, AuthError>;

