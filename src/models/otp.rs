use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::email_otps)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct EmailOtp {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub code_hash: Option<String>,
    pub purpose: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub lang: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::db::schema::email_otps)]
pub struct NewEmailOtp {
    pub user_id: Uuid,
    pub email: String,
    pub code_hash: String,
    pub lang: String,
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
}


