use crate::db::schema::user_totp;
use crate::domain::{AuthFactor, encrypt_token, send_email_setup};
use crate::middleware::RequestExt;
use crate::models::UserTotp;
use crate::services::auth_service::AuthService;
use crate::services::grpc::*;
use base32;
use diesel::prelude::*;
use diesel::upsert::excluded;
use rand::RngCore;
use tonic::{Request, Response, Status};
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::debug;

impl AuthService {
    fn build_totp_secret_and_url(&self, account_name: &str) -> Result<(String, String), Status> {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = vec![0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret_bytes);

        let secret_bytes = Secret::Encoded(secret.clone())
            .to_bytes()
            .map_err(|_| Status::internal("Invalid TOTP secret format"))?;

        let _ = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
            .map_err(|_| Status::internal("Failed to create TOTP instance"))?;

        let url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
            self.config.totp_issuer, account_name, secret, self.config.totp_issuer
        );

        Ok((secret, url))
    }

    pub async fn get_auth_factors_for_user(
        &self,
        request: Request<GetAuthFactorsRequest>,
    ) -> Result<Response<GetAuthFactorsResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let mut conn = self.conn()?;
        debug!("Fetching auth factors for user: {}", auth_ctx.user.id);

        let factors = self
            .ensure_auth_factors(auth_ctx.user.id, &mut conn)
            .map_err(|e| e.to_status())?;

        Ok(Response::new(GetAuthFactorsResponse {
            success: true,
            message: "Authentication factors fetched successfully".to_string(),
            primary_factor: factors.primary_factor,
            secondary_factor: factors.secondary_factor,
        }))
    }

    pub async fn update_auth_factors_for_user(
        &self,
        request: Request<UpdateAuthFactorsRequest>,
    ) -> Result<Response<UpdateAuthFactorsResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let req = request.into_inner();
        let mut conn = self.conn()?;
        debug!("Updating auth factors for user: {}", auth_ctx.user.id);


        let mut factors = self
            .ensure_auth_factors(auth_ctx.user.id, &mut conn)
            .map_err(|e| e.to_status())?;

        let primary = AuthFactor::from_db(&req.primary_factor).map_err(|e| e.to_status())?;
        let secondary = AuthFactor::from_db(&req.secondary_factor).map_err(|e| e.to_status())?;

        if primary == AuthFactor::None {
            return Err(Status::invalid_argument(
                "Primary factor cannot be set to none",
            ));
        }

        if primary == AuthFactor::Totp {
            return Err(Status::invalid_argument(
                "TOTP cannot be used as the primary factor",
            ));
        }

        if secondary != AuthFactor::None && secondary == primary {
            return Err(Status::invalid_argument(
                "Secondary factor must differ from primary factor",
            ));
        }

        if secondary == AuthFactor::Password {
            return Err(Status::invalid_argument(
                "Password cannot be used as a secondary factor",
            ));
        }

        if primary == AuthFactor::EmailOtp && !factors.password_first_login_completed {
            return Err(Status::failed_precondition(
                "Initial password login not completed; cannot switch primary factor yet",
            ));
        }

        if secondary == AuthFactor::None && factors.password_first_login_completed {
            debug!("Secondary factor cleared for user: {}", auth_ctx.user.id);
        }

        let mut totp_secret: String = String::new();
        let mut totp_qr_url: String = String::new();
        let mut message: String = String::new();

        if secondary == AuthFactor::Totp {
            let existing_totp = user_totp::table
                .find(auth_ctx.user.id)
                .first::<UserTotp>(&mut conn)
                .optional()
                .map_err(|e| Status::internal(format!("Failed to load TOTP: {}", e)))?;

            if existing_totp.is_none() {
                let (secret, qr_url) = self.build_totp_secret_and_url(&auth_ctx.user.id.to_string())?;
                let encrypted_secret = encrypt_token(&secret, &self.config.password_pepper)
                    .map_err(|e| {
                        Status::internal(format!("Failed to encrypt TOTP secret: {}", e))
                    })?;

                diesel::insert_into(user_totp::table)
                    .values((
                        user_totp::user_id.eq(auth_ctx.user.id),
                        user_totp::secret_encrypted.eq(encrypted_secret),
                    ))
                    .on_conflict(user_totp::user_id)
                    .do_update()
                    .set(user_totp::secret_encrypted.eq(excluded(user_totp::secret_encrypted)))
                    .execute(&mut conn)
                    .map_err(|e| Status::internal(format!("Failed to store TOTP secret: {}", e)))?;

                totp_secret = secret;
                totp_qr_url = qr_url;
                message = "TOTP secret and QR code generated successfully".to_string();
            }
        }
        if primary == AuthFactor::EmailOtp || secondary == AuthFactor::EmailOtp {
            if auth_ctx.user.email_verified_at.is_none(){
                return Err(Status::invalid_argument(
                        "You need to verify your email first",
                    ));
            }
            send_email_setup(&self.config, &mut conn, &auth_ctx.user, req.lang.clone()).await?;
            message = "Email OTP has been successfully setup".to_string();
        }

        factors = self
            .update_auth_factors(
                auth_ctx.user.id,
                &mut conn,
                primary,
                secondary,
                factors.password_first_login_completed,
            )
            .map_err(|e| e.to_status())?;

        Ok(Response::new(UpdateAuthFactorsResponse {
            success: true,
            message,
            primary_factor: factors.primary_factor,
            secondary_factor: factors.secondary_factor,
            totp_secret,
            totp_qr_url,
        }))
    }
}
