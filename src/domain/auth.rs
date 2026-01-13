use super::validation::{validate_email_address, validate_password_strength};
use super::{generate_salt, hash_password, verify_password};
use super::{AuthError, AuthResult};
use crate::models::User;

pub fn validate_registration_input(email: &str, password: &str) -> AuthResult<()> {
    validate_email_address(email)?;
    validate_password_strength(password)?;
    Ok(())
}

pub fn validate_login_input(email: &str) -> AuthResult<()> {
    validate_email_address(email)?;
    Ok(())
}

pub fn hash_password_with_salt(password: &str, pepper: &str) -> AuthResult<(String, String)> {
    let salt = generate_salt();
    let password_hash = hash_password(password, &salt, pepper)?;
    Ok((password_hash, salt))
}


pub fn verify_user_password(password: &str, user: &User, pepper: &str) -> AuthResult<()> {
    let valid = verify_password(password, &user.password_hash, &user.password_salt, pepper)?;
    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidCredentials)
    }
}
