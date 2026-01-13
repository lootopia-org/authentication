use super::crypto::{decrypt_token, encrypt_token};
use super::errors::{AuthError, AuthResult};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Access,
    Refresh,
    MfaSession,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub roles: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub token_type: TokenType,
    pub context: Option<String>,
}

fn generate_token(
    user_id: Uuid,
    email: &str,
    roles: Vec<String>,
    secret: &str,
    secret_key: &str,
    token_type: TokenType,
    expires_in_minutes: i64,
    context: Option<String>,
) -> AuthResult<String> {
    let now = Utc::now();
    let expiration = now + Duration::minutes(expires_in_minutes);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        roles,
        exp: expiration.timestamp(),
        iat: now.timestamp(),
        token_type,
        context,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AuthError::Cryptography("Failed to generate token".to_string()))?;

    encrypt_token(&token, secret_key)
}

pub fn generate_access_token(
    user_id: Uuid,
    email: &str,
    roles: Vec<String>,
    secret: &str,
    secret_key: &str,
    expires_in_minutes: i64,
) -> AuthResult<String> {
    generate_token(
        user_id,
        email,
        roles,
        secret,
        secret_key,
        TokenType::Access,
        expires_in_minutes,
        None,
    )
}

pub fn generate_refresh_token(
    user_id: Uuid,
    email: &str,
    roles: Vec<String>,
    secret: &str,
    secret_key: &str,
    expires_in_minutes: i64,
) -> AuthResult<String> {
    generate_token(
        user_id,
        email,
        roles,
        secret,
        secret_key,
        TokenType::Refresh,
        expires_in_minutes,
        None,
    )
}

pub fn generate_mfa_session_token(
    user_id: Uuid,
    email: &str,
    secret: &str,
    secret_key: &str,
    expires_in_minutes: i64,
    context: Option<String>,
) -> AuthResult<String> {
    generate_token(
        user_id,
        email,
        Vec::new(),
        secret,
        secret_key,
        TokenType::MfaSession,
        expires_in_minutes,
        context,
    )
}

fn decode_token(token: &str, secret: &str, secret_key: &str) -> AuthResult<Claims> {
    let decrypted_token = decrypt_token(token, secret_key)?;

    let token_data = decode::<Claims>(
        &decrypted_token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        _ => AuthError::InvalidToken,
    })?;

    Ok(token_data.claims)
}

fn verify_token(
    token: &str,
    secret: &str,
    secret_key: &str,
    expected_type: TokenType,
) -> AuthResult<Claims> {
    let claims = decode_token(token, secret, secret_key)?;

    if claims.token_type != expected_type {
        return Err(AuthError::InvalidToken);
    }

    Ok(claims)
}

pub fn verify_access_token(token: &str, secret: &str, secret_key: &str) -> AuthResult<Claims> {
    verify_token(token, secret, secret_key, TokenType::Access)
}

pub fn verify_refresh_token(token: &str, secret: &str, secret_key: &str) -> AuthResult<Claims> {
    verify_token(token, secret, secret_key, TokenType::Refresh)
}

pub fn verify_mfa_session_token(token: &str, secret: &str, secret_key: &str) -> AuthResult<Claims> {
    verify_token(token, secret, secret_key, TokenType::MfaSession)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_token_generation_and_verification() {
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let roles = vec!["user".to_string()];
        let secret = "test_secret";
        let secret_key = "12345678901234567890123456789012";

        let token =
            generate_access_token(user_id, email, roles.clone(), secret, secret_key, 15).unwrap();

        let claims = verify_access_token(&token, secret, secret_key).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.roles, roles);
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    fn test_expired_token() {
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let roles = vec!["user".to_string()];
        let secret = "test_secret";
        let secret_key = "12345678901234567890123456789012";

        let token = generate_access_token(user_id, email, roles, secret, secret_key, -1).unwrap();

        let result = verify_access_token(&token, secret, secret_key);
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }
}
