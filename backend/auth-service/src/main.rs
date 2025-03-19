use axum::Server;
use std::net::SocketAddr;
use dotenvy::dotenv;
use crate::app::build_app;
use crate::config::database::init_pool;

mod app;
mod config;
mod db;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let pool = init_pool();
    let app = build_app(pool).await;
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    println!("Listening on {}", addr);
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}