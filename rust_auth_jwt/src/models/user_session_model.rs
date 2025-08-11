use chrono;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, FromRow, Default)]
pub struct UsersSession {
    pub id: i32,
    pub user_id: i32,
    pub user_uuid: Uuid,
    pub device: String,
    pub ip_address: String,
    pub user_agent: String,
    pub refresh_token: String,
    pub uuid: Uuid,
    pub disponibility: String,
    pub expires_at: chrono::NaiveDateTime,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user: Uuid,
    pub roles: String,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub user: Uuid,
    pub token: String,
    pub exp: usize,
}
