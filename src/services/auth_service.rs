use crate::config::Config;
use crate::db::pool::get_connection;
use crate::db::{schema::*, DbPool};
use crate::domain::{AuthError, AuthFactor, AuthResult};
use crate::models::*;
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use tracing::{debug, error};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthService {
    pub config: Config,
    pub pool: DbPool,
}

impl AuthService {
    pub fn new(config: Config, pool: DbPool) -> Self {
        Self { config, pool }
    } 

    pub fn conn(&self) -> AuthResult<PooledConnection<ConnectionManager<PgConnection>>> {
        Ok(get_connection(&self.pool)?)
    }

    pub(crate) fn get_user_roles(&self, user_id: Uuid) -> AuthResult<Vec<String>> {
        debug!("Fetching roles for user: {}", user_id);

        let roles = user_roles::table
            .filter(user_roles::user_id.eq(user_id))
            .inner_join(roles::table)
            .select(roles::name)
            .load::<String>(&mut self.conn()?)
            .map_err(|e| {
                error!("Failed to fetch user roles: {}", e);
                AuthError::Database(e)
            })?;

        debug!("Found {} roles for user {}", roles.len(), user_id);
        Ok(roles)
    }

    pub(crate) fn ensure_auth_factors(
        &self,
        user_id: Uuid,
        conn: &mut diesel::PgConnection,
    ) -> AuthResult<UserAuthFactors> {
        use crate::db::schema::user_auth_factors::dsl;

        if let Some(existing) = dsl::user_auth_factors
            .find(user_id)
            .first::<UserAuthFactors>(conn)
            .optional()
            .map_err(|e| {
                error!("Failed to fetch auth factors: {}", e);
                AuthError::Database(e)
            })?
        {
            return Ok(existing);
        }

        let defaults = NewUserAuthFactors {
            user_id,
            primary_factor: AuthFactor::Password.as_db_value().to_string(),
            secondary_factor: AuthFactor::None.as_db_value().to_string(),
            password_first_login_completed: false,
        };

        diesel::insert_into(dsl::user_auth_factors)
            .values(&defaults)
            .get_result(conn)
            .map_err(|e| {
                error!("Failed to create default auth factors: {}", e);
                AuthError::Database(e)
            })
    }

    pub(crate) fn update_auth_factors(
        &self,
        user_id: Uuid,
        conn: &mut diesel::PgConnection,
        primary: AuthFactor,
        secondary: AuthFactor,
        password_first_login_completed: bool,
    ) -> AuthResult<UserAuthFactors> {
        use crate::db::schema::user_auth_factors::dsl;

        diesel::insert_into(dsl::user_auth_factors)
            .values(NewUserAuthFactors {
                user_id,
                primary_factor: primary.as_db_value().to_string(),
                secondary_factor: secondary.as_db_value().to_string(),
                password_first_login_completed,
            })
            .on_conflict(dsl::user_id)
            .do_update()
            .set((
                dsl::primary_factor.eq(primary.as_db_value()),
                dsl::secondary_factor.eq(secondary.as_db_value()),
                dsl::password_first_login_completed.eq(password_first_login_completed),
                dsl::updated_at.eq(Utc::now()),
            ))
            .get_result(conn)
            .map_err(|e| {
                error!("Failed to update auth factors: {}", e);
                AuthError::Database(e)
            })
    }

    pub(crate) fn mark_first_login_complete(
        &self,
        conn: &mut diesel::PgConnection,
        user_id: Uuid,
    ) -> AuthResult<()> {
        use crate::db::schema::user_auth_factors::dsl;

        diesel::update(dsl::user_auth_factors.find(user_id))
            .set((
                dsl::password_first_login_completed.eq(true),
                dsl::updated_at.eq(Utc::now()),
            ))
            .execute(conn)
            .map_err(|e| {
                error!("Failed to mark first login complete: {}", e);
                AuthError::Database(e)
            })?;

        Ok(())
    }
}
