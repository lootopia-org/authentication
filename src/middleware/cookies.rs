use cookie::{Cookie, SameSite};
use tonic::metadata::{MetadataMap, MetadataValue};
use tracing::debug;

pub const ACCESS_TOKEN_COOKIE: &str = "access_token";
pub const REFRESH_TOKEN_COOKIE: &str = "refresh_token";
pub const MFA_SESSION_TOKEN: &str = "mfa_session_token";

pub fn create_secure_cookie(name: &str, value: &str, max_age_minutes: i64, secure: bool) -> String {
    let mut cookie = Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::None) // Required for cross-origin with credentials
        .max_age(cookie::time::Duration::minutes(max_age_minutes))
        .build();

    if secure {
        cookie.set_secure(true);
    }

    cookie.to_string()
}

pub fn set_token_cookies(
    metadata: &mut MetadataMap,
    access_token: &str,
    refresh_token: &str,
    mfa_session_token: &str,
) -> Result<(), tonic::Status> {
    let access_cookie = create_secure_cookie(ACCESS_TOKEN_COOKIE, access_token, 15, true);

    metadata.insert(
        "set-cookie",
        MetadataValue::try_from(access_cookie)
            .map_err(|_| tonic::Status::internal("Failed to set access token cookie"))?,
    );

    let refresh_cookie = create_secure_cookie(REFRESH_TOKEN_COOKIE, refresh_token, 10080, true);

    metadata.append(
        "set-cookie",
        MetadataValue::try_from(refresh_cookie)
            .map_err(|_| tonic::Status::internal("Failed to set refresh token cookie"))?,
    );
    
    
    let mfa_session_cookie = create_secure_cookie(MFA_SESSION_TOKEN, mfa_session_token, 10080, true);

    metadata.append(
        "set-cookie",
        MetadataValue::try_from(mfa_session_cookie)
            .map_err(|_| tonic::Status::internal("Failed to set refresh token cookie"))?,
    );


    debug!("Set access and refresh token cookies");
    Ok(())
}

pub fn create_delete_cookie(name: &str) -> String {
    Cookie::build((name, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(cookie::time::Duration::seconds(0))
        .build()
        .to_string()
}

pub fn clear_token_cookies(metadata: &mut MetadataMap) -> Result<(), tonic::Status> {
    let access_delete = create_delete_cookie(ACCESS_TOKEN_COOKIE);
    metadata.insert(
        "set-cookie",
        MetadataValue::try_from(access_delete)
            .map_err(|_| tonic::Status::internal("Failed to clear access token cookie"))?,
    );

    let refresh_delete = create_delete_cookie(REFRESH_TOKEN_COOKIE);
    metadata.append(
        "set-cookie",
        MetadataValue::try_from(refresh_delete)
            .map_err(|_| tonic::Status::internal("Failed to clear refresh token cookie"))?,
    );

    let mfa_delete = create_delete_cookie(MFA_SESSION_TOKEN);
    metadata.append(
        "set-cookie",
        MetadataValue::try_from(mfa_delete)
            .map_err(|_| tonic::Status::internal("Failed to clear refresh token cookie"))?,
    );

    debug!("Cleared authentication cookies");
    Ok(())
}

pub fn parse_cookie_header(cookie_header: &str) -> std::collections::HashMap<String, String> {
    let mut cookies = std::collections::HashMap::new();

    for cookie_str in cookie_header.split(';') {
        let cookie_str = cookie_str.trim();
        if let Ok(cookie) = Cookie::parse(cookie_str) {
            cookies.insert(cookie.name().to_string(), cookie.value().to_string());
        }
    }

    cookies
}

pub fn get_cookie_from_metadata(metadata: &MetadataMap, cookie_name: &str) -> Option<String> {
    metadata
        .get("cookie")?
        .to_str()
        .ok()
        .and_then(|cookie_header| parse_cookie_header(cookie_header).get(cookie_name).cloned())
}
