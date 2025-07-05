//! User model and database operations with unified error handling.
//!
//! This module defines the User struct and provides functions for user creation,
//! password hashing and verification, and CRUD operations using Diesel ORM.
//! All database operations now use the unified error system for consistent
//! error handling, logging, and observability.

use crate::db::schema::users;
use crate::utils::error_new::{AuthServiceError, DatabaseError}; // Add ValidationError
use crate::{log_debug, log_error, log_info, log_warn};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use diesel::prelude::*;
use diesel::{AsChangeset, Insertable, Queryable};
use serde::{Deserialize, Serialize};
use tracing_error::SpanTrace;

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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterData {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Data structure for receiving login data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginData {
    pub username: String,
    pub password: String,
}

impl User {
    /// Creates a new user with a hashed password.
    ///
    /// This function does not interact with the database; it only creates
    /// a User struct with a securely hashed password using Argon2.
    ///
    /// # Arguments
    /// * `username` - The desired username
    /// * `email` - The user's email address
    /// * `password` - The plain text password to hash
    ///
    /// # Returns
    /// A new User instance ready to be saved to the database
    pub fn new(username: &str, email: &str, password: &str) -> Self {
        log_debug!("User Management", "Begin user creation", "user_creation_start");
        let password_hash = User::hash_password(password);
        log_info!(
            "User Management", 
            &format!("Created user object for username: {}", username), 
            "user_object_created"
        );

        User {
            id: None,
            username: username.to_string(),
            email: email.to_string(),
            password_hash,
            is_active: Some(false),
        }
    }

    /// Hashes a password using Argon2 with secure defaults.
    ///
    /// Uses Argon2id variant with random salt generation for maximum security.
    /// This is a CPU-intensive operation by design to resist brute force attacks.
    ///
    /// # Arguments
    /// * `password` - The plain text password to hash
    ///
    /// # Returns
    /// A securely hashed password string suitable for database storage
    ///
    /// # Panics
    /// Panics if password hashing fails (extremely rare, indicates system issues)
    pub fn hash_password(password: &str) -> String {
        log_debug!("User Management", "Starting password hashing", "password_hash_start");
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Password hashing failed - this indicates a serious system error")
            .to_string();

        log_debug!("User Management", "Password hash generated successfully", "password_hash_success");
        hash
    }

    /// Verifies a password against the stored hash.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// # Arguments
    /// * `password` - The plain text password to verify
    ///
    /// # Returns
    /// * `Ok(true)` - Password matches
    /// * `Ok(false)` - Password does not match
    /// * `Err(AuthServiceError)` - Hash parsing or verification error
    pub fn verify_password(&self, password: &str) -> Result<bool, AuthServiceError> {
        log_debug!("User Management", "Starting password verification", "password_verify_start");

        // This will now work because:
        // 1. PasswordHash::new returns Result<_, argon2::password_hash::Error>
        // 2. You have From<argon2::password_hash::Error> for ValidationError
        // 3. You have From<ValidationError> for AuthServiceError
        // 4. The ? operator will use this conversion chain automatically
        let parsed_hash = PasswordHash::new(&self.password_hash)?;

        let is_verified = Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok();

        if is_verified {
            log_debug!("User Management", "Password verification successful", "password_verify_success");
        } else {
            log_debug!("User Management", "Password verification failed", "password_verify_failure");
        }

        Ok(is_verified)
    }

    /// Saves the user to the database with transaction safety.
    ///
    /// Creates a new user record in the database within a transaction
    /// to ensure data consistency. Uses the unified error system for
    /// consistent error handling and observability.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    ///
    /// # Returns
    /// * `Ok(usize)` - Number of rows affected (should be 1)
    /// * `Err(AuthServiceError)` - Database operation failed
    pub fn save(&self, conn: &mut SqliteConnection) -> Result<usize, AuthServiceError> {
        log_debug!(
            "User Management",
            &format!("Saving user to database: {}", self.username),
            "user_save_start"
        );

        let result = conn.transaction(|conn| {
            diesel::insert_into(users::table)
                .values(self)
                .execute(conn)
        }).map_err(|e| {
            log_error!(
                "User Management",
                &format!("Failed to save user {}: {}", self.username, e),
                "user_save_error"
            );
            DatabaseError::Query {
                source: e,
                span: SpanTrace::capture(),
            }
        })?;

        log_info!(
            "User Management", 
            &format!("User {} saved successfully", self.username), 
            "user_save_success"
        );

        Ok(result)
    }

    /// Finds a user by username with unified error handling.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `username_str` - Username to search for
    ///
    /// # Returns
    /// * `Ok(User)` - User found
    /// * `Err(AuthServiceError)` - User not found or database error
    pub fn find_by_username(
        conn: &mut SqliteConnection, 
        username_str: &str
    ) -> Result<Self, AuthServiceError> {
        log_debug!(
            "User Management", 
            &format!("Searching for user by username: {}", username_str), 
            "find_by_username_start"
        );

        use crate::db::schema::users::dsl::*;
        
        let user = users
            .filter(username.eq(username_str))
            .first(conn)
            .map_err(|e| {
                match e {
                    diesel::result::Error::NotFound => {
                        log_debug!(
                            "User Management",
                            &format!("User not found by username: {}", username_str),
                            "find_by_username_not_found"
                        );
                    }
                    _ => {
                        log_error!(
                            "User Management",
                            &format!("Database error finding user by username {}: {}", username_str, e),
                            "find_by_username_error"
                        );
                    }
                }
                DatabaseError::Query {
                    source: e,
                    span: SpanTrace::capture(),
                }
            })?;

        log_info!(
            "User Management", 
            &format!("User found by username: {}", username_str), 
            "find_by_username_success"
        );

        Ok(user)
    }

    /// Finds a user by email with unified error handling.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `email_str` - Email address to search for
    ///
    /// # Returns
    /// * `Ok(User)` - User found
    /// * `Err(AuthServiceError)` - User not found or database error
    pub fn find_by_email(
        conn: &mut SqliteConnection, 
        email_str: &str
    ) -> Result<Self, AuthServiceError> {
        log_debug!(
            "User Management", 
            &format!("Searching for user by email: {}", email_str), 
            "find_by_email_start"
        );

        use crate::db::schema::users::dsl::*;
        
        let user = users
            .filter(email.eq(email_str))
            .first(conn)
            .map_err(|e| {
                match e {
                    diesel::result::Error::NotFound => {
                        log_debug!(
                            "User Management",
                            &format!("User not found by email: {}", email_str),
                            "find_by_email_not_found"
                        );
                    }
                    _ => {
                        log_error!(
                            "User Management",
                            &format!("Database error finding user by email {}: {}", email_str, e),
                            "find_by_email_error"
                        );
                    }
                }
                DatabaseError::Query {
                    source: e,
                    span: SpanTrace::capture(),
                }
            })?;

        log_info!(
            "User Management", 
            &format!("User found by email: {}", email_str), 
            "find_by_email_success"
        );

        Ok(user)
    }

    /// Activates the user's account by setting `is_active` to true.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    ///
    /// # Returns
    /// * `Ok(())` - Account activated successfully
    /// * `Err(AuthServiceError)` - Database operation failed
    pub fn activate(&self, conn: &mut SqliteConnection) -> Result<(), AuthServiceError> {
        log_debug!(
            "User Management", 
            &format!("Activating account for user: {}", self.email), 
            "user_activate_start"
        );

        use crate::db::schema::users::dsl::*;
        
        diesel::update(users.filter(email.eq(&self.email)))
            .set(is_active.eq(true))
            .execute(conn)
            .map_err(|e| {
                log_error!(
                    "User Management",
                    &format!("Failed to activate account for {}: {}", self.email, e),
                    "user_activate_error"
                );
                DatabaseError::Query {
                    source: e,
                    span: SpanTrace::capture(),
                }
            })?;

        log_info!(
            "User Management", 
            &format!("Account activated successfully for: {}", self.email), 
            "user_activate_success"
        );

        Ok(())
    }

    /// Updates an existing user record in the database.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    ///
    /// # Returns
    /// * `Ok(())` - User updated successfully
    /// * `Err(AuthServiceError)` - User has no ID or database error
    pub fn update(&self, conn: &mut SqliteConnection) -> Result<(), AuthServiceError> {
        log_debug!(
            "User Management", 
            &format!("Updating user record: {}", self.username), 
            "user_update_start"
        );

        use crate::db::schema::users::dsl::*;
        
        let user_id = self.id.ok_or_else(|| {
            log_warn!(
                "User Management", 
                &format!("Attempted to update user {} without ID", self.username), 
                "user_update_no_id"
            );
            AuthServiceError::Database(DatabaseError::Query {
                source: diesel::result::Error::NotFound,
                span: SpanTrace::capture(),
            })
        })?;

        diesel::update(users.filter(id.eq(user_id)))
            .set(self)
            .execute(conn)
            .map_err(|e| {
                log_error!(
                    "User Management",
                    &format!("Failed to update user {}: {}", self.username, e),
                    "user_update_error"
                );
                DatabaseError::Query {
                    source: e,
                    span: SpanTrace::capture(),
                }
            })?;

        log_info!(
            "User Management", 
            &format!("User {} updated successfully", self.username), 
            "user_update_success"
        );

        Ok(())
    }

    /// Sets a new password (hashes it) and updates the user in the database.
    ///
    /// This method handles the complete password update flow including
    /// fetching the user ID if needed and updating the database record.
    ///
    /// # Arguments
    /// * `conn` - Database connection
    /// * `new_password` - The new plain text password
    ///
    /// # Returns
    /// * `Ok(())` - Password updated successfully
    /// * `Err(AuthServiceError)` - Database operation failed
    pub fn set_password_and_update(
        &mut self,
        conn: &mut SqliteConnection,
        new_password: &str,
    ) -> Result<(), AuthServiceError> {
        log_debug!(
            "User Management", 
            &format!("Updating password for user: {}", self.username), 
            "password_update_start"
        );

        // Hash the new password
        self.password_hash = User::hash_password(new_password);

        // If we don't yet have an id, fetch it from the DB
        if self.id.is_none() {
            let persisted = User::find_by_username(conn, &self.username)?;
            self.id = persisted.id;
        }

        // Now safe to call update
        self.update(conn)?;

        log_info!(
            "User Management", 
            &format!("Password updated successfully for user: {}", self.username), 
            "password_update_success"
        );

        Ok(())
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
    fn find_nonexistent_user_returns_error() {
        let mut conn = get_in_memory_conn();
        
        let result = User::find_by_username(&mut conn, "nonexistent");
        assert!(result.is_err());
        
        // Verify it's the correct error type
        if let Err(AuthServiceError::Database(DatabaseError::Query { source, .. })) = result {
            match source {
                diesel::result::Error::NotFound => {
                    // Expected
                }
                _ => panic!("Expected NotFound error"),
            }
        } else {
            panic!("Expected Database error");
        }
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
    fn update_without_id_fails() {
        let mut conn = get_in_memory_conn();
        let user = User::new("dave", "dave@example.com", "Pass123!");
        // Don't save, so no ID
        
        let result = user.update(&mut conn);
        assert!(result.is_err());
        
        if let Err(AuthServiceError::Database(DatabaseError::Query { source, .. })) = result {
            match source {
                diesel::result::Error::NotFound => {
                    // Expected
                }
                _ => panic!("Expected NotFound error for user without ID"),
            }
        } else {
            panic!("Expected Database error");
        }
    }

    #[test]
    fn set_password_and_update() {
        let mut conn = get_in_memory_conn();
        let mut user = User::new("dan", "dan@example.com", "OldPass1!");
        user.save(&mut conn).unwrap();

        user.set_password_and_update(&mut conn, "NewPass2!").unwrap();
        let fetched = User::find_by_username(&mut conn, "dan").unwrap();
        assert!(fetched.verify_password("NewPass2!").unwrap());
        assert!(!fetched.verify_password("OldPass1!").unwrap());
    }
}