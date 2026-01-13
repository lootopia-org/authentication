use std::collections::HashMap;
use chrono::{ Duration, Utc};
use diesel::RunQueryDsl;
use tonic::Status;
use crate::{
    Config, db::schema::email_otps::{self}, domain::{Email, generate_otp_code, hash_string}, models::{NewEmailOtp, User}, services::{EMAIL_OTP_LOGIN_PURPOSE, EMAIL_OTP_SETUP_PURPOSE, EMAIL_VERIFICATION_PURPOSE, PASSWORD_RESET_PURPOSE}
};


pub async fn send_email_setup(
    config: &Config,
    conn: &mut diesel::PgConnection,
    user: &User,
    lang: String,
) -> Result<(), Status> {
    let new_otp = NewEmailOtp {
        user_id: user.id,
        email: user.email.clone(),
        code_hash: String::new(),
        lang: lang.clone(),
        purpose: EMAIL_OTP_SETUP_PURPOSE.to_string(),
        expires_at: Utc::now(),
    };
    
    diesel::insert_into(email_otps::table)
    .values(&new_otp)
    .execute(conn)
    .map_err(|e| Status::internal(format!("Failed to create OTP: {}", e)))?;
    
    
    let email = Email::new(config, user.email.clone(), "otp".to_string());
    let _ = email.send(
            "otp_setup_email".to_string(),
            HashMap::from([
                ("EMAIL".to_string(), user.email.clone()),
                ("lang".to_string(), lang.clone()),
            ]),
        )
       .await;

    Ok(())
}


pub async fn send_email_otp_code(
    config: &Config,
    conn: &mut diesel::PgConnection,
    user: &User,
    purpose: String,
    lang: String,
) -> Result<(), Status> {
    let otp_code = generate_otp_code();
    let code_hash = hash_string(&otp_code);

    let new_otp = NewEmailOtp {
        user_id: user.id,
        email: user.email.clone(),
        code_hash,
        lang: lang.clone(),
        purpose: purpose.clone(),
        expires_at: Utc::now() + Duration::minutes(10),
    };

    diesel::insert_into(email_otps::table)
        .values(&new_otp)
        .execute(conn)
        .map_err(|e| Status::internal(format!("Failed to create OTP: {}", e)))?;

    let email = Email::new(config, user.email.clone(), "otp code".to_string());
    let _ = email
        .send(
            get_email_otp_template(&purpose),
            HashMap::from([
                ("OTP_CODE".to_string(), otp_code),
                ("lang".to_string(), lang.clone()),
            ]),
        )
        .await;
    Ok(())
}

fn get_email_otp_template(purpose: &str) -> String {
    match purpose {
        EMAIL_VERIFICATION_PURPOSE => "verify_email".to_string(),
        EMAIL_OTP_LOGIN_PURPOSE => "otp_email".to_string(),
        PASSWORD_RESET_PURPOSE => "reset_email".to_string(),
        _ => "otp_email".to_string(),
    }
}
