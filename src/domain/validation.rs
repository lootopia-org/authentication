use super::errors::{AuthError, AuthResult};
use validator::ValidateEmail;

const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_PASSWORD_LENGTH: usize = 128;
const MAX_EMAIL_LENGTH: usize = 255;

pub fn validate_email_address(email: &str) -> AuthResult<String> {
    if email.is_empty() {
        return Err(AuthError::InvalidInput("Email cannot be empty".to_string()));
    }

    if email.len() > MAX_EMAIL_LENGTH {
        return Err(AuthError::InvalidInput(format!(
            "Email must be at most {} characters",
            MAX_EMAIL_LENGTH
        )));
    }

    if !email.validate_email() {
        return Err(AuthError::InvalidInput("Invalid email format".to_string()));
    }

    Ok(email.to_string())
}

pub fn validate_password_strength(password: &str) -> AuthResult<()> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(AuthError::InvalidInput(format!(
            "Password must be at least {} characters",
            MIN_PASSWORD_LENGTH
        )));
    }

    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(AuthError::InvalidInput(format!(
            "Password must be at most {} characters",
            MAX_PASSWORD_LENGTH
        )));
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());

    if !has_uppercase || !has_lowercase || !has_digit {
        return Err(AuthError::InvalidInput(
            "Password must contain at least one uppercase letter, one lowercase letter, and one digit".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_totp_code(code: &str) -> AuthResult<()> {
    if code.len() != 6 {
        return Err(AuthError::InvalidInput(
            "TOTP code must be exactly 6 digits".to_string(),
        ));
    }

    if !code.chars().all(|c| c.is_numeric()) {
        return Err(AuthError::InvalidInput(
            "TOTP code must contain only digits".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_uuid_format(uuid_str: &str) -> AuthResult<uuid::Uuid> {
    uuid::Uuid::parse_str(uuid_str).map_err(|_| AuthError::InvalidUserId)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        assert!(validate_email_address("user@example.com").is_ok());
        assert!(validate_email_address("test.email+tag@domain.co.uk").is_ok());
    }

    #[test]
    fn test_invalid_email() {
        assert!(validate_email_address("").is_err());
        assert!(validate_email_address("not-an-email").is_err());
        assert!(validate_email_address("@example.com").is_err());
        assert!(validate_email_address("user@").is_err());
    }

    #[test]
    fn test_valid_password() {
        assert!(validate_password_strength("Password123").is_ok());
        assert!(validate_password_strength("SecureP@ssw0rd").is_ok());
    }

    #[test]
    fn test_invalid_password() {
        assert!(validate_password_strength("short").is_err());
        assert!(validate_password_strength("alllowercase123").is_err());
        assert!(validate_password_strength("ALLUPPERCASE123").is_err());
        assert!(validate_password_strength("NoNumbers").is_err());
    }

    #[test]
    fn test_valid_totp_code() {
        assert!(validate_totp_code("123456").is_ok());
        assert!(validate_totp_code("000000").is_ok());
    }

    #[test]
    fn test_invalid_totp_code() {
        assert!(validate_totp_code("12345").is_err());
        assert!(validate_totp_code("1234567").is_err());
        assert!(validate_totp_code("12345a").is_err());
    }
}
