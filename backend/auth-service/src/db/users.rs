//! User model and database operations.
//!
//! This module defines the User struct and provides functions for user creation,
//! password hashing and verification, and CRUD operations using Diesel ORM.
//! Logging and error handling are consistent with the rest of the codebase.

use crate::db::schema::users;
use crate::{log_debug, log_error, log_info, log_warn};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use diesel::prelude::*;
use diesel::{AsChangeset, Insertable, Queryable};
use serde::{Deserialize, Serialize};

/// Represents a user in the database.
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Option<i32>,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: Option<bool>,
}

/// Data structure for receiving registration data.
#[derive(Serialize, Deserialize, Debug, Clone)]  // added Clone
pub struct RegisterData {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Data structure for receiving login data.
#[derive(Serialize, Deserialize, Debug, Clone)]  // added Clone
pub struct LoginData {
    pub username: String,
    pub password: String,
}

impl User {
    /// Creates a new user with a hashed password.
    pub fn new(username: &str, email: &str, password: &str) -> Self {
        log_debug!("User Management", "Begin user creation", "success");
        let password_hash = User::hash_password(password);
        log_info!("User Management", "Create user object", "success");

        User {
            id: None,
            username: username.to_string(),
            email: email.to_string(),
            password_hash,
            is_active: Some(false),
        }
    }

    /// Hashes a password using Argon2.
    pub fn hash_password(password: &str) -> String {
        log_debug!("User Management", "Password hashing", "success");
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Password hashing failed")
            .to_string();

        log_debug!("User Management", "Password hash generated", "success");
        hash
    }

    /// Verifies a password against the stored hash.
    pub fn verify_password(&self, password: &str) -> Result<bool, argon2::password_hash::Error> {
        log_debug!("User Management", "Begin password verification", "success");

        let parsed_hash = match PasswordHash::new(&self.password_hash) {
            Ok(hash) => hash,
            Err(e) => {
                log_error!(
                    "User Management",
                    &format!("Parse password hash: {}", e),
                    "failure"
                );
                return Err(e);
            }
        };

        let is_verified = Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok();

        if is_verified {
            log_debug!("User Management", "Password verification", "success");
        } else {
            log_debug!("User Management", "Password verification", "failure");
        }

        Ok(is_verified)
    }

    /// Saves the user in the database.
    pub fn save(&self, conn: &mut SqliteConnection) -> Result<usize, diesel::result::Error> {
        log_debug!(
            "User Management",
            "Begin saving user to database",
            "success"
        );

        conn.transaction(|conn| {
            diesel::insert_into(users::table)
                .values(self)
                .execute(conn)
                .map(|rows| {
                    log_info!("User Management", "Insert user record", "success");
                    rows
                })
                .map_err(|e| {
                    log_error!(
                        "User Management",
                        &format!("Insert user record: {}", e),
                        "failure"
                    );
                    e
                })
        })
    }

    /// Finds a user by username in the database.
    pub fn find_by_username(conn: &mut SqliteConnection, username_str: &str) -> QueryResult<Self> {
        log_debug!("User Management", "Query user by username", "success");
        use crate::db::schema::users::dsl::*;
        users
            .filter(username.eq(username_str))
            .first(conn)
            .map(|user| {
                log_info!("User Management", "Find user by username", "success");
                user
            })
            .map_err(|e| {
                log_debug!(
                    "User Management",
                    &format!("Find user by username: {}", e),
                    "failure"
                );
                e
            })
    }

    /// Finds a user by email in the database.
    pub fn find_by_email(conn: &mut SqliteConnection, email_str: &str) -> QueryResult<Self> {
        log_debug!("User Management", "Query user by email", "success");
        use crate::db::schema::users::dsl::*;
        users
            .filter(email.eq(email_str))
            .first(conn)
            .map(|user| {
                log_info!("User Management", "Find user by email", "success");
                user
            })
            .map_err(|e| {
                log_debug!(
                    "User Management",
                    &format!("Find user by email: {}", e),
                    "failure"
                );
                e
            })
    }

    /// Activates the user's account by setting `is_active` to true.
    pub fn activate(&self, conn: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
        log_debug!("User Management", "Begin account activation", "success");
        use crate::db::schema::users::dsl::*;
        diesel::update(users.filter(email.eq(&self.email)))
            .set(is_active.eq(true))
            .execute(conn)
            .map(|_| {
                log_info!("User Management", "Activate user account", "success");
                ()
            })
            .map_err(|e| {
                log_error!(
                    "User Management",
                    &format!("Activate user account: {}", e),
                    "failure"
                );
                e
            })
    }

    /// Updates an existing user record in the database.
    pub fn update(&self, conn: &mut SqliteConnection) -> QueryResult<()> {
        log_debug!("User Management", "Begin user record update", "success");
        use crate::db::schema::users::dsl::*;
        if let Some(user_id) = self.id {
            diesel::update(users.filter(id.eq(user_id)))
                .set(self)
                .execute(conn)
                .map(|_| {
                    log_info!("User Management", "Update user record", "success");
                    ()
                })
                .map_err(|e| {
                    log_error!(
                        "User Management",
                        &format!("Update user record: {}", e),
                        "failure"
                    );
                    e
                })
        } else {
            log_warn!("User Management", "Update user without ID", "failure");
            Err(diesel::result::Error::NotFound)
        }
    }

    /// Sets a new password (hashes it) and updates the user in the database.
    pub fn set_password_and_update(
        &mut self,
        conn: &mut SqliteConnection,
        new_password: &str,
    ) -> Result<(), diesel::result::Error> {
        // hash the new password
        self.password_hash = User::hash_password(new_password);

        // if we don't yet have an id, fetch it from the DB
        if self.id.is_none() {
            let persisted = User::find_by_username(conn, &self.username)?;
            self.id = persisted.id;
        }

        // now safe to call update
        self.update(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::connection::SimpleConnection;
    use diesel::sqlite::SqliteConnection;

    /// Helper to spin up an in-memory SQLite DB with a `users` table.
    fn get_in_memory_conn() -> SqliteConnection {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.batch_execute(r#"
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_active BOOLEAN
            );
        "#).unwrap();
        conn
    }

    #[test]
    fn new_and_verify_password() {
        let user = User::new("alice", "alice@example.com", "Secret123!");
        assert_eq!(user.username, "alice");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.is_active, Some(false));
        assert!(user.verify_password("Secret123!").unwrap());
        assert!(!user.verify_password("bad password").unwrap());
    }

    #[test]
    fn save_and_find_by_username_and_email() {
        let mut conn = get_in_memory_conn();
        let user = User::new("bob", "bob@example.com", "Password1!");
        assert_eq!(user.save(&mut conn).unwrap(), 1);

        let by_user = User::find_by_username(&mut conn, "bob").unwrap();
        assert_eq!(by_user.email, "bob@example.com");

        let by_email = User::find_by_email(&mut conn, "bob@example.com").unwrap();
        assert_eq!(by_email.username, "bob");
    }

    #[test]
    fn activate_and_update_record() {
        let mut conn = get_in_memory_conn();
        let user = User::new("carol", "carol@example.com", "Pwd123!");
        user.save(&mut conn).unwrap();

        user.activate(&mut conn).unwrap();
        let activated = User::find_by_email(&mut conn, "carol@example.com").unwrap();
        assert_eq!(activated.is_active, Some(true));

        let mut updated = activated;
        updated.username = "carol2".into();
        updated.update(&mut conn).unwrap();
        let fetched = User::find_by_username(&mut conn, "carol2").unwrap();
        assert_eq!(fetched.email, "carol@example.com");
    }

    #[test]
    fn set_password_and_update() {
        let mut conn = get_in_memory_conn();
        let mut user = User::new("dan", "dan@example.com", "OldPass1!");
        user.save(&mut conn).unwrap();

        user.set_password_and_update(&mut conn, "NewPass2!").unwrap();
        let fetched = User::find_by_username(&mut conn, "dan").unwrap();
        assert!(fetched.verify_password("NewPass2!").unwrap());
    }
}