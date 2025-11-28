use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::header::HeaderMap;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Extension;
use std::net::SocketAddr;
use tower_cookies::{self, Cookie};

use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use sqlx::postgres::PgPool;

use crate::models::user_model::UserClaims;
use crate::models::user_session_model::{Claims, RefreshClaims, UsersSession};

pub async fn test_middleware(
    Extension(pool): Extension<PgPool>,
    jar: CookieJar,
    cookies: tower_cookies::Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut req: Request,
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
            match decode::<RefreshClaims>(
                refrsh_jwt_str,
                &DecodingKey::from_secret("secret".as_ref()),
                &validation,
            ) {
                Ok(_r) => {
                    return (StatusCode::FORBIDDEN, "refresh needed".to_string()).into_response();
                }
                Err(err) => {
                    // check if refresh is valid
                    eprintln!("erorr middleware {:?}", err);

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

       SELECT * FROM user_sessions  WHERE user_uuid = $1  AND user_agent=$2 AND ip_address = $3

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

            return (StatusCode::FORBIDDEN, "relog needed").into_response();
        }
    }

    let user_claims = UserClaims {
        user: jwt.claims.user,
        roles: jwt.claims.roles,
    };

    req.extensions_mut().insert(user_claims);

    eprintln!("isok go next");
    next.run(req).await
}
