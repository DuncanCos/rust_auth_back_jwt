use axum::{
    routing::{delete, get, put},
    Router,
};

use crate::controllers::sessions_controllers;

pub fn sessions_routing() -> Router {
    let app = Router::new()
        .route("/users", get(sessions_controllers::all_sessions))
        .route(
            "/user/session/{id}",
            get(sessions_controllers::sessions_from_user),
        )
        .route("/user/{id}", get(sessions_controllers::one_session))
        .route("/user/{id}", put(sessions_controllers::modify_sessions))
        .route("/user/{id}", delete(sessions_controllers::delete_sessions));
    app
}
