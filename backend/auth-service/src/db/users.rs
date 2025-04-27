use crate::db::schema::users;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use diesel::prelude::*;
use diesel::{AsChangeset, Insertable, Queryable};
use serde::{Deserialize, Serialize};
use crate::{log_info, log_warn, log_error, log_debug};

/// Represents a user in the database.
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Option<i32>, // ID is optional for new users
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: Option<bool>, // Whether the account is activated
}

/// Data structure for receiving registration data.
#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterData {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Data structure for receiving login data.
#[derive(Serialize, Deserialize, Debug)]
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
            is_active: Some(false), // New account is initially inactive
        }
    }

    /// Hashes a password using Argon2.
    fn hash_password(password: &str) -> String {
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
                log_error!("User Management", &format!("Parse password hash: {}", e), "failure");
                return Err(e);
            }
        };
        
        let is_verified = Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok();
        
        if is_verified {
            log_debug!("User Management", "Password verification", "success");
        } else {
            log_debug!("User Management", "Password verification", "failure");
        }
        
        Ok(is_verified)
    }

    /// Saves the user in the database.
    pub fn save(&self, conn: &mut SqliteConnection) -> Result<usize, diesel::result::Error> {
        log_debug!("User Management", "Begin saving user to database", "success");
        
        conn.transaction(|conn| {
            diesel::insert_into(users::table)
                .values(self)
                .execute(conn)
                .map(|rows| {
                    log_info!("User Management", "Insert user record", "success");
                    rows
                })
                .map_err(|e| {
                    log_error!("User Management", &format!("Insert user record: {}", e), "failure");
                    e
                })
        })
    }

    /// Finds a user by username in the database.
    pub fn find_by_username(conn: &mut SqliteConnection, username_str: &str) -> QueryResult<Self> {
        log_debug!("User Management", "Query user by username", "success");
        use crate::db::schema::users::dsl::*;
        users.filter(username.eq(username_str))
            .first(conn)
            .map(|user| {
                log_info!("User Management", "Find user by username", "success");
                user
            })
            .map_err(|e| {
                log_debug!("User Management", &format!("Find user by username: {}", e), "failure");
                e
            })
    }

    /// Finds a user by email in the database.
    pub fn find_by_email(conn: &mut SqliteConnection, email_str: &str) -> QueryResult<Self> {
        log_debug!("User Management", "Query user by email", "success");
        use crate::db::schema::users::dsl::*;
        users.filter(email.eq(email_str))
            .first(conn)
            .map(|user| {
                log_info!("User Management", "Find user by email", "success");
                user
            })
            .map_err(|e| {
                log_debug!("User Management", &format!("Find user by email: {}", e), "failure");
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
                log_error!("User Management", &format!("Activate user account: {}", e), "failure");
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
                    log_error!("User Management", &format!("Update user record: {}", e), "failure");
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
        self.password_hash = User::hash_password(new_password);
        self.update(conn)
    }
}