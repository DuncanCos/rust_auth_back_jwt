use sqlx::postgres::PgPoolOptions;
mod controllers;
mod middlewares;
mod models;
mod routes;

use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use dotenvy;
use std::net::SocketAddr;

#[tokio::main]

async fn main() {
    dotenvy::dotenv().ok();
    let _testingenv: String = dotenvy::var("TEST").unwrap();
    let dbconnection: String = dotenvy::var("DB_CONNECTION").unwrap();
    println!("Hello, world!");

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Impossible d'initialiser le logger");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dbconnection)
        .await
        .expect("error whit db connection");

    println!("Connected to db");

    // build our application with a single route
    let app = routes::routing(pool);

    // run our app with hyper, listening globally on port 8000
    println!("server launched on http://127.0.0.1:8080");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
