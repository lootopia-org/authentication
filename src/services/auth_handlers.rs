use crate::db::schema::*;
use crate::domain::auth::{
    hash_password_with_salt, validate_login_input, validate_registration_input,
    verify_user_password,
};
use crate::domain::*;
use crate::middleware::cookies::{
    ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, clear_token_cookies, get_cookie_from_metadata, set_token_cookies
};
use crate::models::{
    EmailOtp, NewRefreshToken, NewUser, NewUserRole, RefreshToken, Role, User, UserTotp,
};
use crate::services::auth_service::AuthService;
use crate::services::{ACCESS_TOKEN_MINUTES, EMAIL_OTP_LOGIN_PURPOSE, MFA_SESSION_MINUTES, REFRESH_TOKEN_MINUTES, grpc::*};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

impl AuthService {
    pub async fn register_user(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let mut conn = self.conn()?;
        info!("Registration attempt for email: {}", req.email);

        validate_registration_input(&req.email, &req.password).map_err(|e| e.to_status())?;

        let existing_user = users::table
            .filter(users::email.eq(&req.email))
            .first::<User>(&mut conn)
            .optional()
            .map_err(|e| {
                error!("Database error checking existing user: {}", e);
                AuthError::Database(e).to_status()
            })?;

        if existing_user.is_some() {
            warn!("Registration failed: email already exists: {}", req.email);
            return Ok(Response::new(RegisterResponse {
                success: false,
                message: "User with this email already exists".to_string(),
            }));
        }

        let (password_hash, salt) =
            hash_password_with_salt(&req.password, &self.config.password_pepper).map_err(|e| {
                error!("Password hashing error: {}", e);
                e.to_status()
            })?;

        let new_user = NewUser {
            email: req.email.clone(),
            password_hash,
            password_salt: salt,
        };

        let user: User = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(&mut conn)
            .map_err(|e| {
                error!("Failed to create user: {}", e);
                AuthError::Database(e).to_status()
            })?;

        debug!("User created with ID: {}", user.id);

        let default_role = roles::table
            .filter(roles::name.eq("user"))
            .first::<Role>(&mut conn)
            .map_err(|e| {
                error!("Failed to find default role: {}", e);
                AuthError::Database(e).to_status()
            })?;

        let new_user_role = NewUserRole {
            user_id: user.id,
            role_id: default_role.id,
        };

        diesel::insert_into(user_roles::table)
            .values(&new_user_role)
            .execute(&mut conn)
            .map_err(|e| {
                error!("Failed to assign default role: {}", e);
                AuthError::Database(e).to_status()
            })?;

        self.update_auth_factors(
            user.id,
            &mut conn,
            AuthFactor::Password,
            AuthFactor::None,
            false,
        )
        .map_err(|e| e.to_status())?;

        info!("User registration successful: {}", req.email);

        Ok(Response::new(RegisterResponse {
            success: true,
            message: "User registered successfully".to_string(),
        }))
    }

    pub async fn login_user(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let session_claims = get_cookie_from_metadata(
            request.metadata(),
            ACCESS_TOKEN_COOKIE,
        )
        .filter(|t| !t.is_empty())
        .map(|token| {
            verify_mfa_session_token(
                &token,
                &self.config.jwt_secret,
                &self.config.jwt_secret_key,
            )
            .map_err(|e| e.to_status())
        })
        .transpose()?;
        let req = request.into_inner();
        let mut conn = self.conn()?;
        info!("Login attempt for email: {}", req.email);

        validate_login_input(&req.email).map_err(|e| e.to_status())?;

        let user = users::table
            .filter(users::email.eq(&req.email))
            .first::<User>(&mut conn)
            .optional()
            .map_err(|e| {
                error!("Database error during login: {}", e);
                AuthError::Database(e).to_status()
            })?
            .ok_or_else(|| {
                warn!("Login failed: invalid credentials for {}", req.email);
                AuthError::InvalidCredentials.to_status()
            })?;

        if !user.is_active {
            warn!("Login failed: inactive account for {}", req.email);
            return Err(AuthError::AccountInactive.to_status());
        }

        let mut factors = self
            .ensure_auth_factors(user.id, &mut conn)
            .map_err(|e| e.to_status())?;

        let configured_primary =
            AuthFactor::from_db(&factors.primary_factor).map_err(|e| e.to_status())?;
        let configured_secondary =
            AuthFactor::from_db(&factors.secondary_factor).map_err(|e| e.to_status())?;

        let primary_factor = if !factors.password_first_login_completed {
            AuthFactor::Password
        } else {
            configured_primary
        };

        let session_context = if let Some(ref claims) = session_claims {
            if claims.sub != user.id.to_string() {
                return Err(Status::unauthenticated(
                    "MFA session token does not match user",
                ));
            }
            claims
                .context
                .as_ref()
                .map(|ctx| MfaSessionContext::from_json(ctx).map_err(|e| e.to_status()))
                .transpose()?
        } else {
            None
        };

        let role_names = self.get_user_roles(user.id).map_err(|e| e.to_status())?;

        if let Some(context) = session_context {
            match context.stage {
                MfaSessionStage::PrimaryEmailOtp => {
                    let code = req
                        .email_otp_code
                        .as_deref()
                        .ok_or_else(|| Status::invalid_argument("Email OTP code is required"))?;

                    self.consume_login_email_otp(
                        &mut conn,
                        user.id,
                        code,
                        EMAIL_OTP_LOGIN_PURPOSE,
                    )?;

                    if configured_secondary == AuthFactor::None {
                        return self.login_success_response(&user, &role_names, &mut conn, "Login successful");
                    }

                    return self
                        .handle_mfa_factor(
                            configured_secondary,
                            MfaSessionStage::Secondary {
                                factor: configured_secondary,
                            },
                            &mut conn,
                            &user,
                            &role_names,
                            &req,
                            EMAIL_OTP_LOGIN_PURPOSE,
                        )
                        .await;
                }
                MfaSessionStage::Secondary { factor } => {
                    return self
                        .handle_mfa_factor(
                            factor,
                            MfaSessionStage::Secondary { factor },
                            &mut conn,
                            &user,
                            &role_names,
                            &req,
                            EMAIL_OTP_LOGIN_PURPOSE,
                        )
                        .await;
                }
            }
        }

        match primary_factor {
            AuthFactor::Password | AuthFactor::None => {
                verify_user_password(&req.password, &user, &self.config.password_pepper).map_err(
                    |e| {
                        if let AuthError::InvalidCredentials = e {
                            warn!("Login failed: invalid password for {}", req.email);
                        }
                        e.to_status()
                    },
                )?;

                debug!("Password verified for user: {}", user.id);

                if !factors.password_first_login_completed {
                    self.mark_first_login_complete(&mut conn, user.id)
                        .map_err(|e| e.to_status())?;
                    factors.password_first_login_completed = true;
                }

                if configured_secondary == AuthFactor::None {
                    return self.login_success_response(&user, &role_names, &mut conn, "Login successful");
                }

                self.handle_mfa_factor(
                    configured_secondary,
                    MfaSessionStage::Secondary {
                        factor: configured_secondary,
                    },
                    &mut conn,
                    &user,
                    &role_names,
                    &req,
                    EMAIL_OTP_LOGIN_PURPOSE,
                )
                .await
            }
            AuthFactor::EmailOtp => {
                self.handle_mfa_factor(
                    AuthFactor::EmailOtp,
                    MfaSessionStage::PrimaryEmailOtp,
                    &mut conn,
                    &user,
                    &role_names,
                    &req,
                    EMAIL_OTP_LOGIN_PURPOSE,
                )
                .await
            }
            AuthFactor::Totp => {
                Err(Status::failed_precondition(
                    "TOTP cannot be used as a primary factor",
                ))
            }
        }
    }

    async fn verify_factor(
        &self,
        factor: AuthFactor,
        conn: &mut diesel::PgConnection,
        user: &User,
        req: &LoginRequest,
        purpose: &str,
    ) -> Result<bool, Status> {
        match factor {
            AuthFactor::Totp => {
                if let Some(code) = req.totp_code.as_deref() {
                    self.verify_totp_code_for_login(conn, user.id, code)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            AuthFactor::EmailOtp => {
                if let Some(code) = req.email_otp_code.as_deref() {
                    self.consume_login_email_otp(conn, user.id, code, purpose)?;
                    Ok(true)
                } else {
                    let lang = self.get_email_otp_lang(conn, user.id)?;
                    send_email_otp_code(
                        &self.config,
                        conn,
                        user,
                        EMAIL_OTP_LOGIN_PURPOSE.to_string(),
                        lang,
                    )
                    .await?;
                    Ok(false)
                }
            }
            AuthFactor::Password => {
                verify_user_password(&req.password, user, &self.config.password_pepper)
                    .map_err(|e| e.to_status())?;
                Ok(true)
            }
            AuthFactor::None => Ok(true),
        }
    }

    async fn handle_mfa_factor(
        &self,
        factor: AuthFactor,
        stage: MfaSessionStage,
        conn: &mut diesel::PgConnection,
        user: &User,
        role_names: &[String],
        req: &LoginRequest,
        purpose: &str,
    ) -> Result<Response<LoginResponse>, Status> {
        self.ensure_secondary_factor_ready(factor, conn, user.id)?;

        let verified = self.verify_factor(factor, conn, user, req, purpose).await?;

        if verified {
            self.login_success_response(user, role_names, conn, "Login successful")
        } else {
            let tokens = self.build_mfa_session_token(user, stage.clone())?;

            let mut response = Response::new(LoginResponse {
                success: false,
                message: "Additional authentication required".to_string(),
                tokens: Some(tokens.clone()),
            });

            set_token_cookies(response.metadata_mut(), &String::new(), &String::new(), &tokens.mfa_session_token)?;
            Ok(response)
        }
    }

    pub fn get_email_otp_lang(
        &self,
        conn: &mut diesel::PgConnection,
        user_id: Uuid,
    ) -> Result<String, Status> {
        let lang = email_otps::table
            .filter(email_otps::user_id.eq(user_id))
            .filter(email_otps::purpose.eq("email_otp_setup"))
            .select(email_otps::lang)
            .first::<String>(conn)
            .map_err(|e| {
                Status::internal(format!("Failed to get email OTP lang: {}", e))
            })?;
        Ok(lang)
    }

    fn login_success_response(
        &self,
        user: &User,
        role_names: &[String],
        conn: &mut diesel::PgConnection,
        message: &str,
    ) -> Result<Response<LoginResponse>, Status> {
        let (access_token, refresh_token, tokens) = self.mint_token_pair(user, role_names, conn)?;

        info!("Login successful for user {}", user.email);

        let mut response = Response::new(LoginResponse {
            success: true,
            message: message.to_string(),
            tokens: Some(tokens),
        });
        
        set_token_cookies(response.metadata_mut(), &access_token, &refresh_token, &String::new().as_str())?;

        Ok(response)
    }

    pub async fn logout_user(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        debug!("Logout request received");

        let refresh_token = get_cookie_from_metadata(request.metadata(), REFRESH_TOKEN_COOKIE).ok_or_else(|| {
            warn!("No refresh token in request body or cookie");
            Status::unauthenticated("Refresh token required")
        })?;
        

        let mut conn = self.conn()?;
        verify_refresh_token(
            &refresh_token,
            &self.config.jwt_secret,
            &self.config.jwt_secret_key,
        )
        .map_err(|e| {
            warn!("Invalid refresh token during logout: {}", e);
            e.to_status()
        })?;

        let token_hash = hash_string(&refresh_token);

        let affected = diesel::update(
            refresh_tokens::table.filter(refresh_tokens::token_hash.eq(&token_hash)),
        )
        .set((
            refresh_tokens::revoked.eq(true),
            refresh_tokens::revoked_at.eq(Some(Utc::now())),
        ))
        .execute(&mut conn)
        .map_err(|e| {
            error!("Failed to revoke token: {}", e);
            AuthError::Database(e).to_status()
        })?;

        if affected == 0 {
            return Err(AuthError::InvalidToken.to_status());
        }

        info!("Logout successful");

        let mut response = Response::new(LogoutResponse {
            success: true,
            message: "Logged out successfully".to_string(),
        });

        clear_token_cookies(response.metadata_mut())?;

        Ok(response)
    }

    pub async fn refresh_access_token(
        &self,
        request: Request<RefreshTokenRequest>,
    ) -> Result<Response<RefreshTokenResponse>, Status> {
        debug!("Token refresh request received");

        let refresh_token = get_cookie_from_metadata(request.metadata(), REFRESH_TOKEN_COOKIE).ok_or_else(|| {
                warn!("No refresh token in request body or cookie");
                Status::unauthenticated("Refresh token required")
            })?;

        let mut conn = self.conn()?;

        let claims = verify_refresh_token(
            &refresh_token,
            &self.config.jwt_secret,
            &self.config.jwt_secret_key,
        )
        .map_err(|e| {
            warn!("Invalid refresh token: {}", e);
            e.to_status()
        })?;

        let token_hash = hash_string(&refresh_token);

        let stored_token = refresh_tokens::table
            .filter(refresh_tokens::token_hash.eq(&token_hash))
            .filter(refresh_tokens::revoked.eq(false))
            .filter(refresh_tokens::expires_at.gt(Utc::now()))
            .first::<RefreshToken>(&mut conn)
            .optional()
            .map_err(|e| {
                error!("Database error during token refresh: {}", e);
                AuthError::Database(e).to_status()
            })?
            .ok_or_else(|| {
                warn!("Refresh token not found or expired");
                AuthError::InvalidToken.to_status()
            })?;

        let user_id = validate_uuid_format(&claims.sub).map_err(|e| e.to_status())?;

        let user = users::table
            .find(user_id)
            .first::<User>(&mut conn)
            .map_err(|e| {
                error!("Failed to fetch user during token refresh: {}", e);
                AuthError::Database(e).to_status()
            })?;

        if stored_token.user_id != user.id {
            warn!(
                "Refresh token user mismatch: token for {} used by {}",
                stored_token.user_id, user.id
            );
            return Err(AuthError::InvalidToken.to_status());
        }

        if !user.is_active {
            warn!(
                "Token refresh denied: inactive account for user {}",
                user_id
            );
            return Err(AuthError::AccountInactive.to_status());
        }

        let role_names = self.get_user_roles(user.id).map_err(|e| e.to_status())?;

        diesel::update(refresh_tokens::table.find(stored_token.id))
            .set((
                refresh_tokens::revoked.eq(true),
                refresh_tokens::revoked_at.eq(Some(Utc::now())),
            ))
            .execute(&mut conn)
            .map_err(|e| {
                error!("Failed to revoke old token: {}", e);
                AuthError::Database(e).to_status()
            })?;

        let (new_access_token, new_refresh_token_str, tokens) =
            self.mint_token_pair(&user, &role_names, &mut conn)?;

        info!("Token refresh successful for user: {}", user_id);

        let mut response = Response::new(RefreshTokenResponse {
            success: true,
            message: "Token refreshed successfully".to_string(),
            tokens: Some(tokens),
        });

        set_token_cookies(
            response.metadata_mut(),
            &new_access_token,
            &new_refresh_token_str,
            &String::new()
        )?;

        Ok(response)
    }

    pub async fn verify_access_token(
        &self,
        request: Request<VerifyTokenRequest>,
    ) -> Result<Response<VerifyTokenResponse>, Status> {
        let token = get_cookie_from_metadata(request.metadata(), ACCESS_TOKEN_COOKIE).ok_or_else(|| {
            warn!("No access token in request body or cookie");
            Status::unauthenticated("Access token required")
        })?;
        debug!("Token verification request received");

        let mut conn = self.conn()?;

        let claims = verify_access_token(
            &token,
            &self.config.jwt_secret,
            &self.config.jwt_secret_key,
        )
        .map_err(|e| {
            warn!("Token verification failed: {}", e);
            e.to_status()
        })?;

        let user_id = validate_uuid_format(&claims.sub).map_err(|e| e.to_status())?;

        let user = users::table
            .find(user_id)
            .first::<User>(&mut conn)
            .optional()
            .map_err(|e| {
                error!("Database error during token verification: {}", e);
                AuthError::Database(e).to_status()
            })?;

        if let Some(user) = user {
            if !user.is_active {
                return Ok(Response::new(VerifyTokenResponse {
                    valid: false,
                    message: "Account is inactive".to_string(),
                }));
            }

            Ok(Response::new(VerifyTokenResponse {
                valid: true,
                message: "Token is valid".to_string(),
            }))
        } else {
            Ok(Response::new(VerifyTokenResponse {
                valid: false,
                message: "User not found".to_string(),
            }))
        }
    }

    fn build_mfa_session_token(
        &self,
        user: &User,
        stage: MfaSessionStage,
    ) -> Result<AuthTokens, Status> {
        let ctx = MfaSessionContext { stage };
        let serialized = ctx.to_json().map_err(|e| e.to_status())?;

        let mfa_session_token = generate_mfa_session_token(
            user.id,
            &user.email,
            &self.config.jwt_secret,
            &self.config.jwt_secret_key,
            MFA_SESSION_MINUTES,
            Some(serialized),
        )
        .map_err(|e| e.to_status())?;
        
        Ok(AuthTokens{
            access_token: String::new(),
            refresh_token: String::new(),
            mfa_session_token,
            expires_in: ACCESS_TOKEN_MINUTES * 60,
        })
    }

    fn ensure_secondary_factor_ready(
        &self,
        secondary: AuthFactor,
        conn: &mut diesel::PgConnection,
        user_id: Uuid,
    ) -> Result<(), Status> {
        match secondary {
            AuthFactor::Totp => {
                let has_totp = user_totp::table
                    .find(user_id)
                    .first::<UserTotp>(conn)
                    .optional()
                    .map_err(|e| {
                        error!("Failed to load TOTP for user {}: {}", user_id, e);
                        AuthError::Database(e).to_status()
                    })?
                    .is_some();
                if has_totp {
                    Ok(())
                } else {
                    Err(AuthError::MfaNotConfigured.to_status())
                }
            }
            AuthFactor::EmailOtp => Ok(()),
            AuthFactor::None => Ok(()),
            AuthFactor::Password => Err(Status::failed_precondition(
                "Password is not a valid secondary factor",
            )),
        }
    }

    fn consume_login_email_otp(
        &self,
        conn: &mut diesel::PgConnection,
        user_id: Uuid,
        otp_code: &str,
        purpose: &str,
    ) -> Result<(), Status> {
        let code_hash = hash_string(otp_code);

        let otp = email_otps::table
            .filter(email_otps::user_id.eq(user_id))
            .filter(email_otps::code_hash.eq(&code_hash))
            .filter(email_otps::purpose.eq(purpose))
            .filter(email_otps::consumed_at.is_null())
            .filter(email_otps::expires_at.gt(Utc::now()))
            .first::<EmailOtp>(conn)
            .optional()
            .map_err(|e| {
                error!("Failed to verify email OTP: {}", e);
                AuthError::Database(e).to_status()
            })?;

        let otp: EmailOtp = otp.ok_or_else(|| AuthError::InvalidOtp.to_status())?;

        diesel::update(email_otps::table.find(otp.id))
            .set(email_otps::consumed_at.eq(Some(Utc::now())))
            .execute(conn)
            .map_err(|e| {
                error!("Failed to consume OTP: {}", e);
                AuthError::Database(e).to_status()
            })?;

        Ok(())
    }

    fn verify_totp_code_for_login(
        &self,
        conn: &mut diesel::PgConnection,
        user_id: Uuid,
        code: &str,
    ) -> Result<(), Status> {
        validate_totp_code(code).map_err(|e| e.to_status())?;

        let user_totp = user_totp::table
            .find(user_id)
            .first::<UserTotp>(conn)
            .optional()
            .map_err(|e| {
                error!("Failed to fetch TOTP: {}", e);
                AuthError::Database(e).to_status()
            })?
            .ok_or_else(|| AuthError::MfaNotConfigured.to_status())?;

        let secret = decrypt_totp_secret(&user_totp.secret_encrypted, &self.config.password_pepper)
            .map_err(|e| {
                error!("Failed to decrypt TOTP secret: {}", e);
                e.to_status()
            })?;

        let valid = verify_totp_code(&secret, code).map_err(|e| {
            error!("TOTP verification error: {}", e);
            e.to_status()
        })?;

        if !valid {
            return Err(AuthError::InvalidMfaCode.to_status());
        }

        diesel::update(user_totp::table.find(user_id))
            .set(user_totp::last_used_at.eq(Some(Utc::now())))
            .execute(conn)
            .map_err(|e| {
                error!("Failed to update TOTP last_used: {}", e);
                AuthError::Database(e).to_status()
            })?;

        Ok(())
    }

    fn mint_token_pair(
        &self,
        user: &User,
        role_names: &[String],
        conn: &mut diesel::PgConnection,
    ) -> Result<(String, String, AuthTokens), Status> {
        let refresh_token_str = generate_refresh_token(
            user.id,
            &user.email,
            role_names.to_owned(),
            &self.config.jwt_secret,
            &self.config.jwt_secret_key,
            REFRESH_TOKEN_MINUTES,
        )
        .map_err(|e| {
            error!("Failed to generate refresh token: {}", e);
            e.to_status()
        })?;

        let refresh_expires = Utc::now() + Duration::minutes(REFRESH_TOKEN_MINUTES);
        let refresh_hash = hash_string(&refresh_token_str);

        diesel::insert_into(refresh_tokens::table)
            .values(&NewRefreshToken {
                user_id: user.id,
                token_hash: refresh_hash,
                expires_at: refresh_expires,
            })
            .execute(conn)
            .map_err(|e| {
                error!("Failed to persist refresh token: {}", e);
                AuthError::Database(e).to_status()
            })?;

        let access_token = generate_access_token(
            user.id,
            &user.email,
            role_names.to_owned(),
            &self.config.jwt_secret,
            &self.config.jwt_secret_key,
            ACCESS_TOKEN_MINUTES,
        )
        .map_err(|e| {
            error!("Failed to generate access token: {}", e);
            e.to_status()
        })?;

        let tokens = AuthTokens {
            access_token: access_token.clone(),
            refresh_token: refresh_token_str.clone(),
            mfa_session_token: String::new(),
            expires_in: ACCESS_TOKEN_MINUTES * 60,
        };

        Ok((access_token, refresh_token_str, tokens))
    }
}
