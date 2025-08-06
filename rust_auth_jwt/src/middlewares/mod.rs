use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::header::HeaderMap;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Extension;
use std::net::SocketAddr;
use tower_cookies::{self, Cookie};

use serde::{Deserialize, Serialize};

use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{decode, DecodingKey, Validation,Algorithm};
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
    cookies: tower_cookies::Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> impl IntoResponse {

        // recuperer les 2 cookie  auth et refresh et les met en &str
    if jar.get("auth").is_none() {
        return (StatusCode::UNAUTHORIZED, format!("no cookie")).into_response();
    }
    let auth_cookie = jar.get("auth").unwrap();
    let auth_jwt_str = auth_cookie.value();

    if jar.get("refresh").is_none() {
        return (StatusCode::UNAUTHORIZED, format!("no cookie")).into_response();
    }

    let refresh_cookie = jar.get("refresh").unwrap();
    let refrsh_jwt_str = refresh_cookie.value();



    //recupere ip et user agent

    let ip = addr.ip().to_string();
    let user_agent = headers["user-agent"].to_str().unwrap_or_default();


    // est cence verifier si le auth et ok sinon il verifie si le refresh et ok sinon il reset les cookie et demande a faire un relog
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let jwt = match decode::<Claims>(
        auth_jwt_str,
        &DecodingKey::from_secret("secret".as_ref()),
        &validation,
    ) {
        Ok(r) => r,
        Err(_err) => {
            // check if refresh is valid
            match decode::<Claims>(
                refrsh_jwt_str,
                &DecodingKey::from_secret("secret".as_ref()),
                &validation,
            ) {
                Ok(_r) => {
                    return (StatusCode::FORBIDDEN, "refresh needed".to_string()).into_response();
                }
                Err(_err) => {
                    // check if refresh is valid

                    let mut expired_refresh = Cookie::new("refresh", "");
                    expired_refresh.set_path("/");
                    expired_refresh.set_http_only(true);
                    expired_refresh.set_same_site(tower_cookies::cookie::SameSite::None);
                    expired_refresh.set_secure(false); // mettre true en prod
                    expired_refresh.set_partitioned(true);
                    expired_refresh.make_removal(); // définit l'expiration à une date passée
                    cookies.add(expired_refresh);
                    // Supprime le cookie "refresh"
                    let mut expired_auth = Cookie::new("auth", "");
                    expired_auth.set_path("/");
                    expired_auth.set_http_only(true);
                    expired_auth.set_same_site(tower_cookies::cookie::SameSite::None);
                    expired_auth.set_secure(false); // mettre true en prod
                    expired_auth.set_partitioned(true);
                    expired_auth.make_removal(); // définit l'expiration à une date passée
                    cookies.add(expired_auth);
                    return (StatusCode::FORBIDDEN, "relog needed".to_string()).into_response();
                }
            };

            //return (StatusCode::FORBIDDEN, "relog needed".to_string()).into_response();
        }
    };
    // lier le user email a l'id qui serra liée au user_id de usersession avec les bonnes info (user agent et ip)

    let sql_check = "

       SELECT * FROM user_sessions  WHERE user_id = $1  AND user_agent=$2 AND ip_address = $3

    ";

    match sqlx::query_as::<_, UsersSession>(sql_check)
        .bind(jwt.claims.user)
        .bind(user_agent)
        .bind(ip)
        .fetch_one(&pool)
        .await
    {
        Ok(_users) => {
            // eprintln!("{:?}", users)
        }
        Err(_err) => {
            // eprintln!("Database query failed: {:?}", err);
            let message = "Unable to fetch users middleware".to_string();
            return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }
    }

        eprintln!("isok go next");
        next.run(req).await
}
