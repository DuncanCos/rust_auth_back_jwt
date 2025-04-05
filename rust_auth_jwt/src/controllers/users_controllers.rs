use crate::models::user_model::Users;
use crate::models::user_session_model::UsersSession;
use axum::http::{header, StatusCode};
use axum::{extract, extract::ConnectInfo , extract::Path, response::IntoResponse, Extension, Json, http::header::HeaderMap};

use axum_extra::extract::cookie::{CookieJar, Cookie};
use tower_cookies;
use std::net::SocketAddr;

use sqlx::postgres::PgPool;

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use bcrypt::{hash, verify, DEFAULT_COST};

use log;

use chrono::{prelude::*, Duration};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};

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



pub async fn test_session() -> impl IntoResponse {
    eprintln!("isok test session");
    (StatusCode::OK, "isok session").into_response()
}

pub async fn logout() -> impl IntoResponse {
    (StatusCode::OK, "disconnected").into_response()

    // (StatusCode::EXPECTATION_FAILED, "error while disconnecting").into_response()
}

pub async fn get_session() -> impl IntoResponse {
    (StatusCode::ACCEPTED, format!("no session")).into_response()
}


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user: i32,
    company: String,
    exp: usize,
}

pub async fn login(
    Extension(pool): Extension<PgPool>,
    jar: CookieJar,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    cookies: tower_cookies::Cookies,
    extract::Json(body): extract::Json<LoginUser>,
) -> impl IntoResponse {

    if let Some(jar) = jar.get("jwt_token") {
        log::info!("cookie : {}",jar);
        // yes jar
    }else {
        //no jar
        log::info!("no cookie");
    }

    let mail = body.mail;
    let password = body.password;
    let ip = addr.to_string();
    let user_agent = headers["user-agent"].clone();

    eprintln!("ip {:?} ua {:?} mail {} pass {}", ip, user_agent, mail, password);

    let user = match sqlx::query_as::<_, Users>(
        "SELECT * FROM users WHERE  mail=$1",
    )
    .bind(mail.clone())
    .fetch_one(&pool)
    .await
    {
        Ok(r) => r ,
        Err(e) => {
            eprintln!("error while fetching db {:?}",e);
            Users::default()
            },
    };

    let hash_pass = user.password;

    eprintln!("hash of {} {}",mail ,hash_pass);

    let is_valid= match verify(password,&hash_pass){
        Ok(r) => {r},
        Err(_e) => {
            eprintln!("error verify");
            false}
    };

    if is_valid {
        //TODO create jwt + put things into db usersesions
        //part1 create jwt

        let test_time = Utc::now() + Duration::minutes(20);
        let convert_time = test_time.timestamp();
        
        let refresh_time = Utc::now() + Duration::days(1);
        let refresh_convert_time = refresh_time.timestamp();
       

        let new_claim = Claims{
            user: user.id.clone(),
            company: "autre".to_string(),
            exp: convert_time as usize 
        };

        let refresh_claim = Claims{
            user: user.id.clone(),
            company: "autre".to_string(),
            exp: refresh_convert_time as usize 
        };

        let token = encode(&Header::default(), &new_claim, &EncodingKey::from_secret("secret".as_ref())).unwrap_or_default();
        let refresh_token = encode(&Header::default(), &refresh_claim, &EncodingKey::from_secret("secret".as_ref())).unwrap_or_default();

        eprintln!("token result {}",token);

        //creation de cookie de session
        cookies.add( tower_cookies::Cookie::new("auth", token));
        cookies.add( tower_cookies::Cookie::new("refresh", refresh_token.clone()));
      
        match sqlx::query_as::<_, UsersSession>(
            "INSERT INTO user_sessions (user_id, device, ip_address, user_agent, refresh_token, expires_at) VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '7 days')",
        )
        .bind(user.id)
        .bind("nonedevice")
        .bind(ip)
        .bind(user_agent.to_str().unwrap_or_default())
        .bind(refresh_token)
        .fetch_all(&pool)
        .await
        {
            Ok(r) => (StatusCode::OK, format!("{:?}", r)).into_response(),
            Err(e) => (StatusCode::EXPECTATION_FAILED, format!("{}", e)).into_response(),
        };

        return (StatusCode::OK, "yes token connexion wip").into_response();

    }

    (StatusCode::OK, "no connexion wip").into_response()
}

pub async fn subscribe(
    Extension(pool): Extension<PgPool>,
    jar: CookieJar,
    extract::Json(body): extract::Json<SubscribeUser>,
) -> impl IntoResponse {

    if let Some(jar) = jar.get("jwt_token") {
        log::info!("cookie : {}",jar);
        // yes jar
    }else {
        //no jar
        log::info!("no cookie");
    }

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
