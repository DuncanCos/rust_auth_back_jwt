use axum::{
    routing::{get, post},
    Router,
};

use crate::controllers::auth_controllers;

pub fn auth_routing() -> Router {
    let app = Router::new()
    .route("/subscribe", post(auth_controllers::subscribe))
    .route("/login", post(auth_controllers::login))
    .route("/logout", get(auth_controllers::logout))
    .route("/session", get(auth_controllers::get_session))
    .route("/refresh", get(auth_controllers::refresh_token))
    .route("/finalize/{uuid}", get(auth_controllers::finalise_subscribe))
    .route("/me", get(auth_controllers::access_pages));
    app
}
