use axum::{Extension, Router, routing::{get, post}};
use sqlx::postgres::PgPool;
use tower_http::cors::{CorsLayer, Any, AllowOrigin};

use tower_cookies;


mod users_routes;

use tower_http::trace::{TraceLayer, DefaultMakeSpan, DefaultOnResponse};

use tracing::Level;

use axum::middleware;

use crate::controllers::users_controllers;
use crate::middlewares;

pub fn routing(pool: PgPool) -> Router {


    
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact("http://localhost:5173".parse().unwrap()))
        .allow_methods(vec![http::Method::GET,http::Method::POST, http::Method::OPTIONS])
        .allow_headers(vec![
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
            http::header::CONTENT_TYPE,
            http::header::SET_COOKIE,
            http::header::COOKIE
        ])
        .allow_credentials(true);
    


    let app = Router::new()
        .nest("/users", users_routes::user_routing())
        .layer(middleware::from_fn( middlewares::test_middleware))
        .route("/subscribe", post(users_controllers::subscribe))
        .route("/login", post(users_controllers::login))
        .route("/logout", get(users_controllers::logout))
        .route("/session", get(users_controllers::get_session))
        .route("/refresh",get(users_controllers::refresh_token))
        .route("/me",get(users_controllers::access_pages))
        .layer(Extension(pool))
        .layer(cors)
        .layer(tower_cookies::CookieManagerLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO)) // Log des requêtes entrantes
                .on_response(DefaultOnResponse::new().level(Level::INFO)), // Log des réponses
        );
    app
}

