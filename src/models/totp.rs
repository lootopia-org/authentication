use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::user_totp)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserTotp {
    pub user_id: Uuid,
    pub secret_encrypted: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::db::schema::user_totp)]
pub struct NewUserTotp {
    pub user_id: Uuid,
    pub secret_encrypted: String,
}
