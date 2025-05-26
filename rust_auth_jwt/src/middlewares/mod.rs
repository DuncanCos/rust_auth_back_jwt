use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::header::HeaderMap;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Extension;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use axum_extra::extract::cookie::{Cookie, CookieJar};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use sqlx::postgres::PgPool;

use crate::models::user_session_model::UsersSession;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user: i32,
    company: String,
    exp: usize,
}

pub async fn test_middleware(
    Extension(pool): Extension<PgPool>,
    jar: CookieJar,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let is_valid = true;

    if jar.get("auth").is_none() {
        return (StatusCode::UNAUTHORIZED, format!("no coookie")).into_response();
    }

    let auth_cookie = jar.get("auth").unwrap();
    let jwt_str = auth_cookie.value();
    let ip = addr.ip().to_string();
    let user_agent = headers["user-agent"].to_str().unwrap_or_default();

    let jwt = match decode::<Claims>(
        jwt_str,
        &DecodingKey::from_secret("secret".as_ref()),
        &Validation::default(),
    ) {
        Ok(r) => r,
        Err(_err) => {
            return (StatusCode::FORBIDDEN, "relog needed".to_string()).into_response();
        }
    };

    eprintln!(
        "mail :  {:?} ip : {:?}, user_agent  {:?}",
        jwt.claims.user, ip, user_agent
    );

    // lier le user email a l'id qui serra liée au user_id de usersession avec les bonnes info (user agent et ip)

    let sql_check = "

       SELECT * FROM user_sessions  WHERE user_id = $1  AND user_agent=$2

    ";

    match sqlx::query_as::<_, UsersSession>(sql_check)
        .bind(jwt.claims.user)
        .bind(user_agent)
        .fetch_one(&pool)
        .await
    {
        Ok(users) => {
            eprintln!("{:?}", users)
        }
        Err(err) => {
            eprintln!("Database query failed: {:?}", err);
            let message = "Unable to fetch users".to_string();
            return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }
    }

    if is_valid {
        eprintln!("isok go next");
        next.run(req).await
    } else {
        eprintln!("oskour cant go next");
        (
            StatusCode::UNAUTHORIZED,
            format!("not connected middleware"),
        )
            .into_response()
    }
}
