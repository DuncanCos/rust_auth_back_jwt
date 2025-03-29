use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize, Debug, FromRow)]
pub struct Users {
    pub id: i32,
    pub username: String,
    pub mail: String,
    pub password: String,
    pub created_at: String,
}
