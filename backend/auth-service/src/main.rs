use axum::Server;
use std::net::SocketAddr;
use crate::app::build_app;

mod app;


#[tokio::main]
async fn main() {
    let app = build_app().await;
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    println!("Listening on {}", addr);
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}