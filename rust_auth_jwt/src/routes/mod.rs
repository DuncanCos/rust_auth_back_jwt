use axum::{
    Extension, Router,
};
use sqlx::postgres::PgPool;
use tower_http::cors::CorsLayer;

use http::HeaderValue;
use tower_cookies;

mod sessions_routes;
mod users_routes;
mod auth_routes;

use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};

use tracing::Level;

use axum::middleware;


use crate::middlewares;

pub fn routing(pool: PgPool) -> Router {
    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_static("http://localhost:5173"),
            HeaderValue::from_static("http://127.0.0.1:5173"),
        ])
        .allow_methods(vec![
            http::Method::GET,
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers(vec![
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
            http::header::CONTENT_TYPE,
            http::header::SET_COOKIE,
            http::header::COOKIE,
        ])
        .allow_credentials(true);

    let app = Router::new()
        .nest("/users", users_routes::user_routing())
        .nest("/sessions", sessions_routes::sessions_routing())
        .layer(middleware::from_fn(middlewares::test_middleware))
        .nest("/auth", auth_routes::auth_routing())
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
