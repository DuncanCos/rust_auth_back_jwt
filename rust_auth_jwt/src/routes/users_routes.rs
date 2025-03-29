use axum::{
     routing::{delete, get, post, put}, Router
};



use crate::controllers::users_controllers;

pub fn user_routing() -> Router {
    let app = Router::new()
        .route("/test_session", get(users_controllers::test_session))
        .route("/user", get(users_controllers::users))
        .route("/users", get(users_controllers::all_users))
        .route("/user/{id}", get(users_controllers::one_user))
        .route("/user/{id}", put(users_controllers::modify_user))
        .route("/user", post(users_controllers::create_user))
        .route("/user/{id}", delete(users_controllers::delete_user));
    app
}


