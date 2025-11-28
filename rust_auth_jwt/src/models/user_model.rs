use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, FromRow, Default)]
pub struct Users {
    pub id: i32,
    pub uuid: Uuid,
    pub roles: String,
    pub mail: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug, FromRow, Default)]
pub struct UsersLoginReturn {
    pub roles: String,
    pub mail: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct SubscribeUser {
    pub mail: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct LoginUser {
    pub mail: String,
    pub password: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct BlankUser {
    pub password: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct UserClaims {
    pub user: Uuid,
    pub roles: String,
}
