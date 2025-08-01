use crate::models::user_model::Users;
use crate::models::user_session_model::UsersSession;
use axum::body;
use axum::http::StatusCode;
use axum::{
    extract, extract::ConnectInfo, extract::Path, http::header::HeaderMap, response::IntoResponse,
    Extension, Json,
};

use axum_extra::extract::cookie::CookieJar;
use tokio::time::sleep;
use tower_cookies::{self, Cookie};


use std::net::SocketAddr;
use std::time::Duration as stdDuration;

use sqlx::postgres::PgPool;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;

use bcrypt::{hash, verify, DEFAULT_COST};

use log::{self, error, info};

use chrono::{prelude::*, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

use uuid::Uuid;

use lettre::message::{header, Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};

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

pub async fn get_session() -> impl IntoResponse {
    (StatusCode::ACCEPTED, format!("no session")).into_response()
}

pub async fn access_pages(jar: CookieJar, cookies: tower_cookies::Cookies) -> impl IntoResponse {
    log::info!("coocou");
    if jar.get("refresh").is_none() {
        return (StatusCode::UNAUTHORIZED, format!("no cookie")).into_response();
    }

    let refresh_cookie = jar.get("refresh").unwrap();
    let refrsh_jwt_str = refresh_cookie.value();


    if let Some(jar) = jar.get("auth") {
        log::info!("cookie : {}", jar);
        let jwt_str = jar.value();
        let _jwt = match decode::<Claims>(
            jwt_str,
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::default(),
        ) {
            Ok(r) => r,
            Err(_err) => {
                // Supprime le cookie "refresh"

                match decode::<Claims>(
                    refrsh_jwt_str,
                    &DecodingKey::from_secret("secret".as_ref()),
                    &Validation::default(),
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
        (StatusCode::ACCEPTED, format!("isok")).into_response()
        // yes jar
    } else {
        //no jar
        log::info!("no cookie");
        (StatusCode::NOT_ACCEPTABLE, format!("no cookie")).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user: i32,
    company: String,
    exp: usize,
}

pub async fn login(
    Extension(pool): Extension<PgPool>,
    _jar: CookieJar,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    cookies: tower_cookies::Cookies,
    extract::Json(body): extract::Json<LoginUser>,
) -> impl IntoResponse {
    let mail = body.mail;
    let password = body.password;
    let ip = addr.ip().to_string();
    let user_agent = headers["user-agent"].clone();

    eprintln!(
        "ip {:?} ua {:?} mail {} pass {}",
        ip, user_agent, mail, password
    );

    let user = match sqlx::query_as::<_, Users>("SELECT * FROM users WHERE  mail=$1")
        .bind(mail.clone())
        .fetch_one(&pool)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error while fetching db {:?}", e);
            return (StatusCode::EXPECTATION_FAILED, format!("error while fetching db {:?}", e)).into_response();
           // Users::default()
        }
    };

    let hash_pass = user.password;

    eprintln!("hash of {} {}", mail, hash_pass);

    let is_valid = match verify(password, &hash_pass) {
        Ok(r) => r,
        Err(_e) => {
            eprintln!("error verify");
            false
        }
    };

    if is_valid {
        let test_time = Utc::now() + Duration::minutes(2);
        let convert_time = test_time.timestamp();
        eprintln!("test time {:?}", test_time);

        let refresh_time = Utc::now() + Duration::days(1);
        let refresh_convert_time = refresh_time.timestamp();

        let new_claim = Claims {
            user: user.id.clone(),
            company: "autre".to_string(),
            exp: convert_time as usize,
        };

        let refresh_token = Uuid::new_v4();

        let refresh_claim = Claims {
            user: user.id.clone(),
            company: refresh_token.to_string(),
            exp: refresh_convert_time as usize,
        };

        let token = encode(
            &Header::default(),
            &new_claim,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .unwrap_or_default();
        let refresh_token = encode(
            &Header::default(),
            &refresh_claim,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .unwrap_or_default();

        //creation de cookie de session

        let mut auth_cookie = tower_cookies::Cookie::new("auth", token);
        auth_cookie.set_path("/");
        auth_cookie.set_secure(false); // mettre true en prod avec HTTPS
        auth_cookie.set_partitioned(true);

        auth_cookie.set_same_site(tower_cookies::cookie::SameSite::None);

        auth_cookie.set_http_only(true);

        let mut refresh_cookie = tower_cookies::Cookie::new("refresh", refresh_token.clone());
        refresh_cookie.set_path("/");

        refresh_cookie.set_secure(false); // mettre true en prod avec HTTPS
        refresh_cookie.set_partitioned(true);
        refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::None);

        refresh_cookie.set_http_only(true);

        cookies.add(auth_cookie);

        cookies.add(refresh_cookie);

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

        //TODO delete les users sessions pour qu'il ny en ait que 5 par users

        match sqlx::query_as::<_, UsersSession>(
            "DELETE FROM user_sessions
                WHERE ctid IN (
                SELECT ctid
                FROM user_sessions
                WHERE user_id = $1
                ORDER BY created_at ASC
                OFFSET 5
                )
                RETURNING *;
            ",
        )
        .bind(user.id)
        .fetch_optional(&pool)
        .await
        {
            Ok(Some(session)) => session,
            Ok(None) => {
                println!("No old session to delete.");
                UsersSession::default()
            }
            Err(_err) => {
                println!("Error while deleting: {:?}", _err);
                UsersSession::default()
            }
        };

        return (StatusCode::OK, "connexion ok").into_response();
    }

    (StatusCode::EXPECTATION_FAILED, "nice request").into_response()
}

pub async fn subscribe(
    Extension(pool): Extension<PgPool>,
    jar: CookieJar,
    extract::Json(body): extract::Json<SubscribeUser>,
) -> impl IntoResponse {
    if let Some(jar) = jar.get("jwt_token") {
        log::info!("cookie : {}", jar);
        // yes jar
    } else {
        //no jar
        log::info!("no cookie");
    }

    //todo check if user already exists

    let exists: bool =
        match sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE mail = $1)")
            .bind(&body.mail)
            .fetch_one(&pool)
            .await
        {
            Ok(exists) => exists,
            Err(e) => {
                eprintln!("Erreur SQLX: {:?}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        };

    if exists {
        return (StatusCode::CONFLICT, "User already exists").into_response();
    }

    let hashed_password = hash(body.password, DEFAULT_COST).unwrap_or("notapass".to_string());
    let _info = format!("{} {} {}", body.username, body.mail, hashed_password);

    match sqlx::query_as::<_, Users>(
        "INSERT INTO Users (username, mail, password) VALUES ($1,$2,$3)",
    )
    .bind(body.username)
    .bind(body.mail.clone())
    .bind(hashed_password)
    .fetch_one(&pool)
    .await 
    {
        Ok(r) => {
            //todo send email to user

            let email = match build_email(body.mail.as_str(),build_email_html(r.mail.clone(), r.id).as_str()) {
                Ok(msg) => msg,
                Err(e) => {
                    let body = json!({"error": format!("Erreur de construction de l'email : {}", e)});
                    return (StatusCode::BAD_REQUEST, Json(body)).into_response();
                }
            };
        
            // Config SMTP 
            let creds = Credentials::new(
                "gunner.harris25@ethereal.email".to_string(),
                "cPCgPbFGNfc1EypESW".to_string(),
            );
        
            let mailer = match SmtpTransport::starttls_relay("smtp.ethereal.email") {
                Ok(builder) => builder.port(587).credentials(creds).build(),
                Err(e) => {
                    let body = json!({"error": format!("Erreur de configuration SMTP : {}", e)});
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response();
                }
            };


            // Envoiement de l'email

            match mailer.send(&email) {
                Ok(_) => {
                    let body = json!({"message": "Email envoyé avec succès"});
                    (StatusCode::CREATED, format!("{:?}", r)).into_response()
                }
                Err(e) => {
                    let body = json!({"error": format!("Erreur lors de l'envoi : {}", e)});
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
                }
            }

            
        }
        Err(e) => (StatusCode::EXPECTATION_FAILED, format!("{}", e)).into_response(),
    }
}

fn build_email(destinataire: &str, body: &str) -> Result<Message, String> {
    let from_address: Mailbox = "bernhard.trantow@ethereal.email"
        .parse()
        .map_err(|e| format!("Erreur d'adresse d'expéditeur: {}", e))?;

    let to_address: Mailbox = destinataire
        .parse()
        .map_err(|e| format!("Erreur d'adresse de destinataire: {}", e))?;

    Message::builder()
        .from(from_address)
        .to(to_address)
        .subject("Creation de compte")
        .header(lettre::message::header::ContentType::TEXT_HTML)
        .body(body.to_string())
        .map_err(|e| format!("Erreur lors de la construction du message: {}", e))
}

fn build_email_html(destinataire: String, id_destinataire: i32) -> String {
    let confirmation_url = format!("http://localhost:5173/auth/{}", id_destinataire);

    let mail = format!(
        "<html>
            <head>
                <title>Bienvenue</title>
            </head>
            <body>
                <h1>Bienvenue sur notre site, {} !</h1>
                <p>Merci de vous être inscrit. Votre ID utilisateur est : {}</p>
                <p>Pour finaliser la création de votre compte, veuillez cliquer sur le lien suivant :</p>
                <p><a href=\"{url}\">{url}</a></p>
                <p>Si vous n'avez pas créé de compte, ignorez ce message.</p>
            </body>
        </html>",
        destinataire,
        id_destinataire,
        url = confirmation_url
    );

    mail
}


pub async fn finalise_subscribe(
    Extension(pool): Extension<PgPool>,
    extract::Path(id): extract::Path<i32>,
    jar: CookieJar,
    extract::Json(body): extract::Json<BlankUser>,
) -> impl IntoResponse {
    if let Some(jar) = jar.get("jwt_token") {
        log::info!("cookie : {}", jar);
        // yes jar
    } else {
        //no jar
        log::info!("no cookie");
    }

    let hashed_password = hash(body.password, DEFAULT_COST).unwrap_or("notapass".to_string());
    let _info = format!("{} {} {}", body.username, body.mail, hashed_password);

    match sqlx::query_as::<_, Users>(
        "UPDATE Users SET password = $3 WHERE id = $4",
    )
    .bind(hashed_password)
    .bind(id)
    .fetch_one(&pool)
    .await
    {
        Ok(r) => (StatusCode::CREATED, format!("{:?}", r)).into_response(),
        Err(e) => (StatusCode::EXPECTATION_FAILED, format!("{}", e)).into_response(),
    }
}

pub async fn refresh_token(
    Extension(pool): Extension<PgPool>,
    jar: CookieJar,
    cookies: tower_cookies::Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if jar.get("refresh").is_none() {
        return (StatusCode::UNAUTHORIZED, format!("no cookie")).into_response();
    }

    let refresh_cookie = jar.get("refresh").unwrap();
    let jwt_str = refresh_cookie.value();

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
    // jwt en string
    
    let ip = addr.ip().to_string();
    let user_agent = headers["user-agent"].to_str().unwrap_or_default();
    //let refresh_token_str = jwt.claims.company;
    let user_id = jwt.claims.user;
    println!("user id : {:?} ip add {:?} user_agent: {:?} refresh_token: {:?}", user_id, ip, user_agent, jwt);

    let user_session = match sqlx::query_as::<_, UsersSession>("SELECT * FROM user_sessions  WHERE user_id=$1 AND ip_address=$2 AND user_agent=$3 AND refresh_token=$4  ")
        .bind(user_id)
        .bind(ip)
        .bind(user_agent)
        .bind(jwt_str.to_string())
        .fetch_one(&pool)
        .await{
            Ok(r) => {r},
            Err(e) => { return (StatusCode::EXPECTATION_FAILED, format!("error while fetching db while getting usersession  {:?}", e)).into_response();}
    };


    let session_date_expire = user_session.expires_at;

    let now = Utc::now().naive_utc();

    let diff = now > session_date_expire;


    if !diff {
        let user_session_id = user_session.user_id;

        let refresh_old_time =
            DateTime::from_timestamp(jwt.claims.exp as i64, 0).unwrap_or_default();

        let default_time: DateTime<Utc> = Utc::now();

        if refresh_old_time == default_time {
            return (StatusCode::FORBIDDEN, "relog needed".to_string()).into_response();
        }

        let new_delay_utc = Utc::now() + Duration::minutes(20);
        let new_delay_dt = new_delay_utc.timestamp();

        let new_auth_token = Claims {
            user: user_session_id.clone(),
            company: "autre".to_string(),
            exp: new_delay_dt as usize,
        };

        let new_refresh_token = Uuid::new_v4();

        let refresh_claim = Claims {
            user: user_session_id.clone(),
            company: new_refresh_token.to_string(),
            exp: jwt.claims.exp,
        };

        let token = encode(
            &Header::default(),
            &new_auth_token,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .unwrap_or_default();
        let refresh_token = encode(
            &Header::default(),
            &refresh_claim,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .unwrap_or_default();
        match sqlx::query_as::<_, UsersSession>(
            "UPDATE user_sessions SET refresh_token = $2 WHERE id=$1 ",
        )
        .bind(user_session_id)
        .bind(refresh_token.clone())
        .fetch_all(&pool)
        .await
        {
            Ok(_r) => {
                info!("reset ok")
            }
            Err(err) => {
                error!("error while recreating auth {:?} {:?}", err, user_id);
                return (StatusCode::FORBIDDEN, "relog needed".to_string()).into_response();
            }
        };

        
        let mut auth_cookie = tower_cookies::Cookie::new("auth", token);
        auth_cookie.set_path("/");
        auth_cookie.set_secure(false); // mettre true en prod avec HTTPS
        auth_cookie.set_partitioned(true);

        auth_cookie.set_same_site(tower_cookies::cookie::SameSite::None);

        auth_cookie.set_http_only(true);

        let mut refresh_cookie = tower_cookies::Cookie::new("refresh", refresh_token.clone());
        refresh_cookie.set_path("/");

        refresh_cookie.set_secure(false); // mettre true en prod avec HTTPS
        refresh_cookie.set_partitioned(true);
        refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::None);

        refresh_cookie.set_http_only(true);

        cookies.add(auth_cookie);

        cookies.add(refresh_cookie);
        (StatusCode::OK, "token refreshed".to_string()).into_response()
    } else {
        return (StatusCode::FORBIDDEN, "relog needed".to_string()).into_response();
    }
}

pub async fn logout(
    Extension(pool): Extension<PgPool>,
    jar: CookieJar,
    cookies: tower_cookies::Cookies,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let start_time = Utc::now();

    //TODO a finir le logout supprimer de la session + supprimer cookies
    let refresh_token = jar.get("refresh").unwrap();
    let auth_token = jar.get("auth").unwrap();

    eprintln!(
        "logout ip {:?} ua {:?} refresh {:?} auth {:?}",
        addr.ip(),
        headers["user-agent"],
        refresh_token,
        auth_token
    );

    let auth_jwt_str = auth_token.value();
    let refresh_jwt_str = refresh_token.value();

    let auth_jwt = match decode::<Claims>(
        auth_jwt_str,
        &DecodingKey::from_secret("secret".as_ref()),
        &Validation::default(),
    ) {
        Ok(r) => r,
        Err(_err) => {
            return (StatusCode::FORBIDDEN, "relog needed".to_string()).into_response();
        }
    };

    let id_session = auth_jwt.claims.user;
    let ip = addr.ip().to_string();
    let user_agent = headers["user-agent"].to_str().unwrap_or_default();

    eprintln!(
        "{:?} {} {:?} {} {}",
        id_session, user_agent, ip, refresh_jwt_str, auth_jwt_str
    );
    let _user_session = match sqlx::query_as::<_, UsersSession>("DELETE FROM user_sessions  WHERE user_id=$1 AND ip_address=$2 AND user_agent=$3 RETURNING *")
        .bind(id_session)
        .bind(ip)
        .bind(user_agent)
        .fetch_one(&pool)
        .await{
            Ok(r) => {r},
            Err(_err) => {
                println!("error while deleting {:?}", _err);
                return (StatusCode::FORBIDDEN, "error while deleting".to_string()).into_response();
            }
    };

    // Supprime le cookie "refresh"
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

    timing_attack_delay(start_time);

    (StatusCode::OK, "disconnected").into_response()

    // (StatusCode::EXPECTATION_FAILED, "error while disconnecting").into_response()
}

pub fn timing_attack_delay(start_time: DateTime<Utc>) {
    let ended_timing = Utc::now();
    let time_between = ended_timing.signed_duration_since(start_time);
    if time_between.num_milliseconds() < 750 {
        let time_remaining = 750 - time_between.num_milliseconds();
        std::thread::sleep(stdDuration::from_millis(time_remaining as u64));
    }
}

