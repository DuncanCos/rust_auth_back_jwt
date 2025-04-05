use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono;



#[derive(Serialize, Deserialize, Debug, FromRow, Default)]
pub struct UsersSession {
    pub id: i32,
    pub user_id: i32,
    pub device: String,
    pub ip_address: String,
    pub user_agent: String,
    pub refresh_token: String,
    pub expires_at: chrono::NaiveDateTime,
    pub created_at: chrono::NaiveDateTime,
}
