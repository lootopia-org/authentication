ALTER TABLE user_auth_factors
    DROP COLUMN IF EXISTS totp_enabled,
    DROP COLUMN IF EXISTS email_otp_enabled;

DROP TABLE IF EXISTS user_mfa_settings;

