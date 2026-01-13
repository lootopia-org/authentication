use super::errors::{AuthError, AuthResult};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose, Engine};
use pbkdf2::pbkdf2_hmac;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const SALT_LENGTH: usize = 32;
const HASH_LENGTH: usize = 64;
const ITERATIONS: u32 = 600_000;
const NONCE_LENGTH: usize = 12;

pub fn generate_salt() -> String {
    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().fill(&mut salt);
    hex::encode(salt)
}

pub fn hash_password(password: &str, salt: &str, pepper: &str) -> AuthResult<String> {
    let salt_bytes = hex::decode(salt)
        .map_err(|_| AuthError::Cryptography("Invalid salt format".to_string()))?;

    let password_with_pepper = format!("{}{}", password, pepper);

    let mut hash = vec![0u8; HASH_LENGTH];
    pbkdf2_hmac::<Sha256>(
        password_with_pepper.as_bytes(),
        &salt_bytes,
        ITERATIONS,
        &mut hash,
    );

    Ok(hex::encode(hash))
}

pub fn verify_password(
    password: &str,
    stored_hash: &str,
    salt: &str,
    pepper: &str,
) -> AuthResult<bool> {
    let computed_hash = hash_password(password, salt, pepper)?;

    let computed_bytes = computed_hash.as_bytes();
    let stored_bytes = stored_hash.as_bytes();

    if computed_bytes.len() != stored_bytes.len() {
        return Ok(false);
    }

    Ok(computed_bytes.ct_eq(stored_bytes).into())
}

pub fn encrypt_token(plaintext: &str, secret_key: &str) -> AuthResult<String> {
    let key_bytes = general_purpose::STANDARD
        .decode(secret_key)
        .map_err(|_| AuthError::Cryptography("Invalid base64 key".into()))?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| AuthError::Cryptography("Encryption failed".to_string()))?;

    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);

    Ok(general_purpose::STANDARD.encode(result))
}

pub fn decrypt_token(token: &str, secret_key: &str) -> AuthResult<String> {
    let key_bytes = general_purpose::STANDARD
        .decode(secret_key)
        .map_err(|_| AuthError::Cryptography("Invalid base64 key".to_string()))?;

    let data = general_purpose::STANDARD
        .decode(token)
        .map_err(|_| AuthError::Cryptography("Invalid token format".to_string()))?;

    if data.len() < NONCE_LENGTH {
        return Err(AuthError::Cryptography("Token too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LENGTH);

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AuthError::Cryptography("Decryption failed".to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|_| AuthError::Cryptography("Invalid UTF-8 in decrypted data".to_string()))
}

pub fn hash_string(input: &str) -> String {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_otp_code() -> String {
    let code: u32 = rand::thread_rng().gen_range(100_000..999_999);
    code.to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password123";
        let salt = generate_salt();
        let pepper = "test_pepper";

        let hash = hash_password(password, &salt, pepper).unwrap();
        assert!(!hash.is_empty());

        let is_valid = verify_password(password, &hash, &salt, pepper).unwrap();
        assert!(is_valid);

        let is_invalid = verify_password("wrong_password", &hash, &salt, pepper).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_token_encryption() {
        let plaintext = "sensitive_token_data";
        let key = "12345678901234567890123456789012"; // 32 bytes

        let encrypted = encrypt_token(plaintext, &key).unwrap();
        let decrypted = decrypt_token(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_constant_time_comparison() {
        let password = "test_password";
        let salt = generate_salt();
        let pepper = "pepper";

        let hash1 = hash_password(password, &salt, pepper).unwrap();
        let hash2 = hash_password(password, &salt, pepper).unwrap();

        assert_eq!(hash1, hash2);
    }
}
