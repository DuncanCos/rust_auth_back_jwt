use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, FromRow, Default)]
pub struct Users {
    pub id: i32,
    pub uuid: Uuid,
    pub roles: String,
    pub username: String,
    pub mail: String,
    pub password: String,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Serialize, Deserialize, Debug, FromRow, Default)]
pub struct UsersLoginReturn {
    pub roles: String,
    pub username: String,
    pub mail: String,
}
