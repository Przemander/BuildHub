use diesel::r2d2::{ConnectionManager, Pool};
use diesel::SqliteConnection;
use std::env;

pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

pub fn init_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env or environment variables");
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    Pool::builder()
        .build(manager)
        .expect("Failed to create DB pool.")
}