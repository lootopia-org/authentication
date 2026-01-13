use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::roles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Role {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::db::schema::user_roles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserRole {
    pub user_id: Uuid,
    pub role_id: i32,
    pub assigned_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::db::schema::user_roles)]
pub struct NewUserRole {
    pub user_id: Uuid,
    pub role_id: i32,
}
