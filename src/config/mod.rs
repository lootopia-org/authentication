use std::env;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub grpc_addr: String,
    pub password_pepper: String,
    pub jwt_secret: String,
    pub jwt_secret_key: String,
    pub totp_issuer: String,
    pub resend: String,
    pub db_pool_size: u32,
}

impl Config {
    pub fn from_env() -> Result<Self, env::VarError> {
        let db_pool_size = env::var("DB_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        Ok(Config {
            database_url: env::var("DATABASE_URL")?,
            grpc_addr: env::var("GRPC_ADDR").unwrap_or_else(|_| "0.0.0.0:50051".to_string()),
            password_pepper: env::var("PASSWORD_PEPPER")?,
            jwt_secret: env::var("JWT_SECRET")?,
            jwt_secret_key: env::var("JWT_KEY")?,
            totp_issuer: env::var("TOTP_ISSUER").unwrap_or_else(|_| "AuthService".to_string()),
            resend: env::var("RESEND_API")?,
            db_pool_size,
        })
    }
}

pub fn validate_config(config: &Config) {
    if config.password_pepper.len() < 32 {
        warn!("PASSWORD_PEPPER is shorter than 32 characters, consider using a longer secret");
    }

    if config.jwt_secret.len() < 32 {
        warn!("JWT_SECRET is shorter than 32 characters, consider using a longer secret");
    }

    if config.jwt_secret_key.as_bytes().len() == 32 {
        panic!("JWT_SECRET_KEY must be exactly 32 bytes");
    }
}
