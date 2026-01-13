use crate::config::Config;
use crate::db::DbPool;
use crate::db::pool::get_connection;
use crate::db::schema::users;
use crate::domain::{AuthError, Claims, validate_email_address, validate_uuid_format, verify_access_token};
use crate::middleware::cookies::{get_cookie_from_metadata, ACCESS_TOKEN_COOKIE};
use crate::middleware::rbac::{Permission, RbacLayer};
use crate::models::User;
use diesel::RunQueryDsl;
use diesel::query_dsl::methods::FindDsl;
use tonic::service::Interceptor;
use tonic::{Request, Status};
use tracing::{debug, warn};

pub trait RequestExt {
    fn auth(&self) -> Result<&AuthContext, Status>;
}

impl<T> RequestExt for Request<T> {
    fn auth(&self) -> Result<&AuthContext, Status> {
        self.extensions()
            .get::<AuthContext>()
            .ok_or_else(|| Status::unauthenticated("Authentication required"))
    }
}


#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user: User,
    pub roles: Vec<String>,
}

impl AuthContext {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn is_admin(&self) -> bool {
        self.has_role("admin")
    }

    pub fn is_user(&self, user_id: &str) -> bool {
        self.user.id.to_string() == user_id
    }

    pub fn can_access(&self, target_user_id: &str, permission: Permission) -> Result<(), Status> {
        match permission {
            Permission::Public => Ok(()),
            Permission::Authenticated => Ok(()),
            Permission::SelfOnly => {
                if self.is_user(target_user_id) {
                    debug!(
                        "Self-access granted for user: {} accessing {}",
                        self.user.id, target_user_id
                    );
                    Ok(())
                } else {
                    warn!(
                        "Access denied: User {} attempted to access resources of user {}",
                        self.user.id, target_user_id
                    );
                    Err(Status::permission_denied(
                        "You can only access your own resources",
                    ))
                }
            }
            Permission::SelfOrAdmin => {
                if self.is_admin() || self.is_user(target_user_id) {
                    debug!(
                        "Access granted for user: {} accessing {} (admin={}, self={})",
                        self.user.id,
                        target_user_id,
                        self.is_admin(),
                        self.is_user(target_user_id)
                    );
                    Ok(())
                } else {
                    warn!(
                        "Access denied: User {} (non-admin) attempted to access resources of user {}",
                        self.user.id, target_user_id
                    );
                    Err(Status::permission_denied(
                        "You can only access your own resources or must be an admin",
                    ))
                }
            }
            Permission::Admin => {
                if self.is_admin() {
                    debug!("Admin access granted for user: {} (admin)", self.user.id);
                    Ok(())
                } else {
                    warn!(
                        "Access denied: User {} (roles: {:?}) attempted admin operation",
                        self.user.id, self.roles
                    );
                    Err(Status::permission_denied(
                        "This operation requires administrator privileges",
                    ))
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthMiddleware {
    config: Config,
    pool: DbPool,
}
impl AuthMiddleware {
    pub fn new(config: Config, pool: DbPool) -> Self {
        Self { config, pool }
    }

    fn validate_token_from_metadata<T>(&self, request: &Request<T>) -> Result<Claims, Status> {
        let token =
            get_cookie_from_metadata(request.metadata(), ACCESS_TOKEN_COOKIE).ok_or_else(|| {
                warn!("Missing valid access token");
                Status::unauthenticated("Missing valid access token")
            })?;
        debug!("Validating access token from request cookies");

        let claims =
            verify_access_token(&token, &self.config.jwt_secret, &self.config.jwt_secret_key)
                .map_err(|e| {
                    warn!("Token validation failed: {}", e);
                    match e {
                        AuthError::TokenExpired => {
                            Status::unauthenticated("Token expired. Please refresh your token.")
                        }
                        AuthError::InvalidToken => Status::unauthenticated("Invalid token"),
                        _ => Status::internal("Token validation error"),
                    }
                })?;

        Ok(Claims {
            sub: claims.sub,
            email: claims.email,
            roles: claims.roles,
            exp: claims.exp,
            iat: claims.iat,
            token_type: claims.token_type,
            context: claims.context,
        })
    }
}

impl Interceptor for AuthMiddleware {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        debug!("Request metadata keys: {:?}", req);
        debug!(
            "Extension: {:?}",
            req.extensions().get::<axum::extract::OriginalUri>()
        );

        let original_uri = req.extensions().get::<axum::extract::OriginalUri>();
        let path = if let Some(uri) = original_uri {
            uri.0.path().trim_start_matches('/')
        } else {
            debug!("Original URI not found");
            return Err(Status::unauthenticated("Original URI not found"));
        };

        debug!("Path: {:?}", path);
        let permission = RbacLayer::get_permission(&path);

        if permission == Permission::Public {
            debug!("Public endpoint, skipping authentication");
            return Ok(req);
        }
        
        let auth = self.validate_token_from_metadata(&req)?;
        let user_id = validate_uuid_format(&auth.sub)?;
        let _ = validate_email_address(&auth.email)?;
        
        let mut conn = get_connection(&self.pool).map_err(|e| Status::internal(format!("Database error: {}", e)))?;
        let user = users::table
        .find(user_id)
        .first::<User>(&mut conn)
        .map_err(|e| Status::not_found(format!("User not found: {}", e)))?;
    
        let auth_ctx = AuthContext {
            user,
            roles: auth.roles,
        };
    
        if permission == Permission::Admin || permission == Permission::SelfOnly {
            auth_ctx.can_access(&auth.sub, permission)?;
        }
        req.extensions_mut().insert(auth_ctx);
        
        Ok(req)
    }
}
