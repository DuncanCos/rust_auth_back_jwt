use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono;

#[derive(Serialize, Deserialize, Debug, FromRow, Default)]
pub struct Users {
    pub id: i32,
    pub username: String,
    pub mail: String,
    pub password: String,
    pub created_at: chrono::NaiveDateTime,
}
