use super::errors::{AuthError, AuthResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFactor {
    Password,
    Totp,
    EmailOtp,
    None,
}

impl AuthFactor {
    pub fn as_db_value(self) -> &'static str {
        match self {
            AuthFactor::Password => "password",
            AuthFactor::Totp => "totp",
            AuthFactor::EmailOtp => "email_otp",
            AuthFactor::None => "none",
        }
    }

    pub fn from_db(value: &str) -> AuthResult<Self> {
        match value {
            "password" => Ok(AuthFactor::Password),
            "totp" => Ok(AuthFactor::Totp),
            "email_otp" => Ok(AuthFactor::EmailOtp),
            "none" => Ok(AuthFactor::None),
            other => Err(AuthError::InvalidInput(format!(
                "Unsupported authentication factor: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "stage")]
pub enum MfaSessionStage {
    PrimaryEmailOtp,
    Secondary { factor: AuthFactor },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaSessionContext {
    pub stage: MfaSessionStage,
}

impl MfaSessionContext {
    pub fn to_json(&self) -> AuthResult<String> {
        serde_json::to_string(self)
            .map_err(|e| AuthError::Cryptography(format!("Failed to encode MFA context: {e}")))
    }

    pub fn from_json(raw: &str) -> AuthResult<Self> {
        serde_json::from_str(raw).map_err(|e| {
            AuthError::InvalidInput(format!("Invalid MFA session context payload: {e}"))
        })
    }
}
