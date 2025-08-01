use crate::models::user_model::Users;
use axum::http::StatusCode;
use axum::{
    extract, extract::Path, response::IntoResponse,
    Extension, Json,
};


use std::time::Duration as stdDuration;

use sqlx::postgres::PgPool;

use serde::{Deserialize, Serialize};
use sqlx::FromRow;


use chrono::{prelude::*, Utc};

pub async fn users(Extension(_pool): Extension<PgPool>) -> String {
    String::from("users")
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Body {
    name: String,
}



// const COUNTER_KEY: &str = "counter";

pub async fn test_session() -> impl IntoResponse {
    eprintln!("isok test session");
    (StatusCode::OK, "isok session").into_response()
}


//CRUD BASICS
pub async fn all_users(Extension(pool): Extension<PgPool>) -> impl IntoResponse {
    match sqlx::query_as::<_, Users>("SELECT * FROM users")
        .fetch_all(&pool)
        .await
    {
        Ok(users) => Json(users).into_response(),
        Err(err) => {
            eprintln!("Database query failed: {:?}", err);
            let message = "Unable to fetch users".to_string();
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

pub async fn one_user(
    Extension(pool): Extension<PgPool>,
    Path(id): extract::Path<i32>,
) -> impl IntoResponse {
    match sqlx::query_as::<_, Users>("SELECT * FROM Users WHERE id = $1")
        .bind(id)
        .fetch_all(&pool)
        .await
    {
        Ok(users) => Json(users).into_response(),
        Err(err) => {
            eprintln!("Database query failed: {:?}", err);
            let message = "Unable to fetch users".to_string();
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

pub async fn modify_user(
    Extension(pool): Extension<PgPool>,
    Path(id): extract::Path<i32>,
    extract::Json(body): extract::Json<Body>,
) -> impl IntoResponse {
    match sqlx::query_as::<_, Users>("UPDATE Users SET name = $1 WHERE id = $2")
        .bind(body.name)
        .bind(id)
        .fetch_all(&pool)
        .await
    {
        Ok(_users) => (StatusCode::OK, "user modfied".to_string()).into_response(),
        Err(err) => {
            eprintln!("Database query failed: {:?}", err);
            let message = "Unable to fetch users".to_string();
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

pub async fn create_user(
    Extension(pool): Extension<PgPool>,
    extract::Json(body): extract::Json<Body>,
) -> impl IntoResponse {
    match sqlx::query_as::<_, Users>("INSERT INTO Users (name) VALUES ($1) ")
        .bind(body.name)
        .fetch_all(&pool)
        .await
    {
        Ok(_users) => (StatusCode::OK, "user created".to_string()).into_response(),
        Err(err) => {
            eprintln!("Database query failed: {:?}", err);
            let message = "Unable to fetch users".to_string();
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

pub async fn delete_user(
    Extension(pool): Extension<PgPool>,
    Path(id): extract::Path<i32>,
) -> impl IntoResponse {
    match sqlx::query_as::<_, Users>("DELETE FROM Users  WHERE id = $1")
        .bind(id)
        .fetch_all(&pool)
        .await
    {
        Ok(_users) => (StatusCode::OK, "user deleted".to_string()).into_response(),
        Err(err) => {
            eprintln!("Database query failed: {:?}", err);
            let message = "Unable to fetch users".to_string();
            (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
        }
    }
}

pub fn timing_attack_delay(start_time: DateTime<Utc>) {
    let ended_timing = Utc::now();
    let time_between = ended_timing.signed_duration_since(start_time);
    if time_between.num_milliseconds() < 750 {
        let time_remaining = 750 - time_between.num_milliseconds();
        std::thread::sleep(stdDuration::from_millis(time_remaining as u64));
    }
}
