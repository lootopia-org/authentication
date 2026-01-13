CREATE TABLE user_auth_factors (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    primary_factor TEXT NOT NULL DEFAULT 'password' CHECK (primary_factor IN ('password', 'email_otp', 'totp')),
    secondary_factor TEXT NOT NULL DEFAULT 'none' CHECK (secondary_factor IN ('none', 'email_otp', 'totp')),
    password_first_login_completed BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_user_auth_factors_primary ON user_auth_factors (primary_factor);
CREATE INDEX idx_user_auth_factors_secondary ON user_auth_factors (secondary_factor);

