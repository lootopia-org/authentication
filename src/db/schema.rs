// @generated automatically by Diesel CLI.

diesel::table! {
    email_otps (id) {
        id -> Uuid,
        user_id -> Uuid,
        #[max_length = 255]
        email -> Varchar,
        code_hash -> Nullable<Text>,
        #[max_length = 50]
        purpose -> Varchar,
        expires_at -> Nullable<Timestamptz>,
        consumed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        #[max_length = 255]
        lang -> Varchar,
    }
}

diesel::table! {
    refresh_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        token_hash -> Text,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        revoked -> Bool,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    roles (id) {
        id -> Int4,
        #[max_length = 50]
        name -> Varchar,
        description -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_auth_factors (user_id) {
        user_id -> Uuid,
        primary_factor -> Text,
        secondary_factor -> Text,
        password_first_login_completed -> Bool,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    user_recovery_codes (id) {
        id -> Uuid,
        user_id -> Uuid,
        code_hash -> Text,
        used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    user_roles (user_id, role_id) {
        user_id -> Uuid,
        role_id -> Int4,
        assigned_at -> Timestamptz,
    }
}

diesel::table! {
    user_totp (user_id) {
        user_id -> Uuid,
        secret_encrypted -> Text,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        #[max_length = 255]
        email -> Varchar,
        password_hash -> Text,
        password_salt -> Text,
        email_verified_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        is_active -> Bool,
    }
}

diesel::joinable!(email_otps -> users (user_id));
diesel::joinable!(refresh_tokens -> users (user_id));
diesel::joinable!(user_auth_factors -> users (user_id));
diesel::joinable!(user_recovery_codes -> users (user_id));
diesel::joinable!(user_roles -> roles (role_id));
diesel::joinable!(user_roles -> users (user_id));
diesel::joinable!(user_totp -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    email_otps,
    refresh_tokens,
    roles,
    user_auth_factors,
    user_recovery_codes,
    user_roles,
    user_totp,
    users,
);
