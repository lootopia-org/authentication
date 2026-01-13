use crate::domain::decrypt_token;

use super::errors::{AuthError, AuthResult};
use totp_rs::{Algorithm, Secret, TOTP};

pub fn verify_totp_code(secret: &str, code: &str) -> AuthResult<bool> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|_| AuthError::Cryptography("Invalid TOTP secret format".to_string()))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|_| AuthError::Cryptography("Failed to create TOTP instance".to_string()))?;
    
    println!("TOTP CODE: {}", totp);

    Ok(totp.check_current(code).unwrap_or(false))
}

pub fn decrypt_totp_secret(encrypted: &str, pepper: &str) -> AuthResult<String> {
    let decrypted = decrypt_token(encrypted, pepper)?;

    String::from_utf8(decrypted.into_bytes()).map_err(|_| {
        AuthError::Cryptography("Failed to decrypt TOTP secret - invalid UTF-8".to_string())
    })
}
