use crate::models::user_model::Users;
use axum::http::StatusCode;
use axum::{extract, extract::Path, response::IntoResponse, Extension, Json};
use sqlx::postgres::PgPool;

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use bcrypt::{hash, verify, DEFAULT_COST};

use log;

pub async fn users(Extension(_pool): Extension<PgPool>) -> String {
    String::from("users")
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Body {
    name: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct SubscribeUser {
    username: String,
    mail: String,
    password: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct LoginUser {
    mail: String,
    password: String,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct BlankUser {
    mail: String,
    password: String,
    username: String,
}

// const COUNTER_KEY: &str = "counter";

#[derive(Default, Deserialize, Serialize)]
struct Counter(usize);

pub async fn test_session() -> impl IntoResponse {}

pub async fn logout() -> impl IntoResponse {
    (StatusCode::OK, "disconnected").into_response()

    // (StatusCode::EXPECTATION_FAILED, "error while disconnecting").into_response()
}

pub async fn get_session() -> impl IntoResponse {
    (StatusCode::ACCEPTED, format!("no session")).into_response()
}

pub async fn login(
    Extension(pool): Extension<PgPool>,
    extract::Json(body): extract::Json<LoginUser>,
) -> impl IntoResponse {
    (StatusCode::OK, "no connexion wip").into_response()
}

pub async fn subscribe(
    Extension(pool): Extension<PgPool>,
    extract::Json(body): extract::Json<SubscribeUser>,
) -> impl IntoResponse {
    let hashed_password = hash(body.password, DEFAULT_COST).unwrap_or("notapass".to_string());
    let _info = format!("{} {} {}", body.username, body.mail, hashed_password);

    match sqlx::query_as::<_, Users>(
        "INSERT INTO Users (username, mail, password) VALUES ($1,$2,$3)",
    )
    .bind(body.username)
    .bind(body.mail)
    .bind(hashed_password)
    .fetch_all(&pool)
    .await
    {
        Ok(r) => (StatusCode::CREATED, format!("{:?}", r)).into_response(),
        Err(e) => (StatusCode::EXPECTATION_FAILED, format!("{}", e)).into_response(),
    }
}

pub async fn all_users(Extension(pool): Extension<PgPool>) -> impl IntoResponse {
    match sqlx::query_as::<_, Users>("SELECT * FROM Users")
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

//CRUD BASICS

pub async fn one_user(
    Extension(pool): Extension<PgPool>,
    Path(id): extract::Path<i32>,
) -> impl IntoResponse {
    match sqlx::query_as::<_, Users>("SELECT * FROM Users WHERE id = ?")
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
    match sqlx::query_as::<_, Users>("UPDATE Users SET name = ? WHERE id = ?")
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
    match sqlx::query_as::<_, Users>("INSERT INTO Users (name) VALUES (?) ")
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
    match sqlx::query_as::<_, Users>("DELETE FROM Users  WHERE id = ?")
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
