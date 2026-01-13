use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::user_auth_factors)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserAuthFactors {
    pub user_id: Uuid,
    pub primary_factor: String,
    pub secondary_factor: String,
    pub password_first_login_completed: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = crate::db::schema::user_auth_factors)]
pub struct NewUserAuthFactors {
    pub user_id: Uuid,
    pub primary_factor: String,
    pub secondary_factor: String,
    pub password_first_login_completed: bool,
}
