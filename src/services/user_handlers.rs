use std::collections::HashMap;

use crate::db::schema::*;
use crate::domain::*;
use crate::middleware::{RequestExt};
use crate::models::{EmailOtp, NewEmailOtp};
use crate::services::auth_service::AuthService;
use crate::services::{EMAIL_VERIFICATION_PURPOSE, grpc::*};
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use tonic::{Request, Response, Status};
use tracing::debug;

impl AuthService {
    pub async fn update_user_email(
        &self,
        request: Request<UpdateUserEmailRequest>,
    ) -> Result<Response<UpdateUserEmailResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let req = request.into_inner()
        let mut conn = self.conn()?;
    
        debug!("Update user email request for ID: {}", auth_ctx.user.id);
    
        if req.new_email.is_empty() {
            return Err(Status::invalid_argument("Email cannot be empty"));
        }
    
        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            diesel::update(users::table.find(auth_ctx.user.id))
                .set((
                    users::email.eq(&req.new_email),
                    users::email_verified_at.eq(None::<DateTime<Utc>>),
                    users::updated_at.eq(Utc::now()),
                ))
                .execute(conn)?;
            
            diesel::update(
                refresh_tokens::table.filter(refresh_tokens::user_id.eq(auth_ctx.user.id))
            )
            .set((
                refresh_tokens::revoked.eq(true),
                refresh_tokens::revoked_at.eq(Some(Utc::now())),
            ))
            .execute(conn)?;
            
            Ok(())
        })
        .map_err(|e| Status::internal(format!("Failed to update user email: {}", e)))?;
    
        let lang = self.get_email_otp_lang(&mut conn, auth_ctx.user.id)?;
        send_email_otp_code(
            &self.config,
            &mut conn,
            &auth_ctx.user,
            EMAIL_VERIFICATION_PURPOSE.to_string(),
            lang,
        ).await?;

        Ok(Response::new(UpdateUserEmailResponse {
            success: true,
            message: "Email updated successfully. Please verify your new email address.".to_string(),
        }))
    }

    pub async fn change_user_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<ChangePasswordResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let req = request.into_inner();

        debug!(
            "Change password request for user ID: {}",
            auth_ctx.user.id
        );

        let password_valid = verify_password(
            &req.current_password,
            &auth_ctx.user.password_hash,
            &auth_ctx.user.password_salt,
            &self.config.password_pepper,
        )
        .map_err(|e| Status::invalid_argument(format!("Password verification error: {}", e)))?;

        if !password_valid {
            return Err(Status::unauthenticated("Invalid current password"));
        }

        let new_salt = generate_salt();
        let new_password_hash =
            hash_password(&req.new_password, &new_salt, &self.config.password_pepper)
                .map_err(|e| Status::internal(format!("Failed to hash password: {}", e)))?;

        diesel::update(users::table.find(auth_ctx.user.id))
            .set((
                users::password_hash.eq(&new_password_hash),
                users::password_salt.eq(&new_salt),
                users::updated_at.eq(Utc::now()),
            ))
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to update password: {}", e)))?;

        diesel::update(refresh_tokens::table.filter(refresh_tokens::user_id.eq(auth_ctx.user.id)))
            .set((
                refresh_tokens::revoked.eq(true),
                refresh_tokens::revoked_at.eq(Some(Utc::now())),
            ))
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to revoke tokens: {}", e)))?;

        Ok(Response::new(ChangePasswordResponse {
            success: true,
            message: "Password changed successfully".to_string(),
        }))
    }

    pub async fn delete_user_account(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let auth_ctx = request.auth()?;

        debug!(
            "Delete user request for ID: {}",
            auth_ctx.user.id
        );

        diesel::delete(users::table.find(auth_ctx.user.id))
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to delete user: {}", e)))?;

        Ok(Response::new(DeleteUserResponse {
            success: true,
            message: "User deleted successfully".to_string(),
        }))
    }

    pub async fn send_email_verification_code(
        &self,
        request: Request<SendEmailVerificationRequest>,
    ) -> Result<Response<SendEmailVerificationResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let req = request.into_inner();

        debug!("Send email verification for user ID: {}", auth_ctx.user.id);

        if auth_ctx.user.email_verified_at.is_some() {
            return Ok(Response::new(SendEmailVerificationResponse {
                success: false,
                message: "Email already verified".to_string(),
            }));
        }

        let otp_code = generate_otp_code();
        let code_hash = hash_string(&otp_code);

        let new_otp = NewEmailOtp {
            user_id: auth_ctx.user.id,
            email: auth_ctx.user.email.clone(),
            code_hash,
            lang: req.lang.clone(),
            purpose: "email_verification".to_string(),
            expires_at: Utc::now() + Duration::minutes(15),
        };

        diesel::insert_into(email_otps::table)
            .values(&new_otp)
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to create OTP: {}", e)))?;

        let email = Email::new(
            &self.config,
            auth_ctx.user.email.clone(),
            "Verify your email".to_string(),
        );
        let _ = email
            .send(
                "verify_email".to_string(),
                HashMap::from([
                    ("OTP_CODE".to_string(), otp_code),
                    ("lang".to_string(), req.lang),
                ]),
            )
            .await;

        Ok(Response::new(SendEmailVerificationResponse {
            success: true,
            message: "Verification email sent".to_string(),
        }))
    }

    pub async fn verify_user_email(
        &self,
        request: Request<VerifyEmailRequest>,
    ) -> Result<Response<VerifyEmailResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let req = request.into_inner();

        debug!("Verify email for user ID: {}", auth_ctx.user.id);

        let code_hash = hash_string(&req.otp_code);

        let otp = email_otps::table
            .filter(email_otps::user_id.eq(auth_ctx.user.id))
            .filter(email_otps::code_hash.eq(&code_hash))
            .filter(email_otps::purpose.eq("email_verification"))
            .filter(email_otps::consumed_at.is_null())
            .filter(email_otps::expires_at.gt(Utc::now()))
            .first::<EmailOtp>(&mut self.conn()?)
            .optional()
            .map_err(|e| Status::internal(format!("Failed to verify OTP: {}", e)))?;

        if otp.is_none() {
            return Ok(Response::new(VerifyEmailResponse {
                success: false,
                message: "Invalid or expired OTP code".to_string(),
            }));
        }

        let otp = otp.unwrap();

        diesel::update(email_otps::table.find(otp.id))
            .set(email_otps::consumed_at.eq(Some(Utc::now())))
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to consume OTP: {}", e)))?;

        diesel::update(users::table.find(auth_ctx.user.id))
            .set((
                users::email_verified_at.eq(Some(Utc::now())),
                users::updated_at.eq(Utc::now()),
            ))
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to verify email: {}", e)))?;

        Ok(Response::new(VerifyEmailResponse {
            success: true,
            message: "Email verified successfully".to_string(),
        }))
    }

    pub async fn reset_user_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<ResetPasswordResponse>, Status> {
        let auth_ctx = request.auth().cloned()?;
        let req = request.into_inner();
        let code_hash = hash_string(&req.otp_code);

        if auth_ctx.user.email_verified_at.is_none(){
            return Err(Status::invalid_argument("You need to verify your email first"));
        }


        let otp = email_otps::table
            .filter(email_otps::user_id.eq(auth_ctx.user.id))
            .filter(email_otps::code_hash.eq(&code_hash))
            .filter(email_otps::purpose.eq("password_reset"))
            .filter(email_otps::consumed_at.is_null())
            .filter(email_otps::expires_at.gt(Utc::now()))
            .first::<EmailOtp>(&mut self.conn()?)
            .optional()
            .map_err(|e| Status::internal(format!("Failed to verify OTP: {}", e)))?;

        if otp.is_none() {
            return Ok(Response::new(ResetPasswordResponse {
                success: false,
                message: "Invalid or expired reset code".to_string(),
            }));
        }

        let otp = otp.unwrap();

        diesel::update(email_otps::table.find(otp.id))
            .set(email_otps::consumed_at.eq(Some(Utc::now())))
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to consume OTP: {}", e)))?;

        let new_salt = generate_salt();
        let new_password_hash =
            hash_password(&req.new_password, &new_salt, &self.config.password_pepper)
                .map_err(|e| Status::internal(format!("Failed to hash password: {}", e)))?;

        diesel::update(users::table.find(auth_ctx.user.id))
            .set((
                users::password_hash.eq(&new_password_hash),
                users::password_salt.eq(&new_salt),
                users::updated_at.eq(Utc::now()),
            ))
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to update password: {}", e)))?;

        diesel::update(refresh_tokens::table.filter(refresh_tokens::user_id.eq(auth_ctx.user.id)))
            .set((
                refresh_tokens::revoked.eq(true),
                refresh_tokens::revoked_at.eq(Some(Utc::now())),
            ))
            .execute(&mut self.conn()?)
            .map_err(|e| Status::internal(format!("Failed to revoke tokens: {}", e)))?;

        Ok(Response::new(ResetPasswordResponse {
            success: true,
            message: "Password reset successfully".to_string(),
        }))
    }
}
