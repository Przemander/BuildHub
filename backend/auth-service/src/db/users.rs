//! User model and database operations with unified error handling.
//!
//! This module defines the User struct and provides functions for user creation,
//! password hashing and verification, and CRUD operations using Diesel ORM.
//! All database operations now use the unified error system for consistent
//! error handling, logging, and observability.

use crate::db::schema::users;
use crate::utils::error_new::{AuthServiceError, DatabaseError};
use crate::utils::log_new::Log; // Nowy system logowania
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use diesel::prelude::*;
use diesel::{AsChangeset, Insertable, Queryable};
use serde::{Deserialize, Serialize};
use tracing_error::SpanTrace;
use crate::metricss::database_metrics::user;
use crate::utils::telemetry::{db_operation_span, SpanExt};

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
        Log::event(
            "DEBUG",
            "User Management",
            "Begin user creation",
            "user_creation_start",
            "new"
        );
        
        let password_hash = User::hash_password(password);
        
        Log::event(
            "INFO",
            "User Management",
            &format!("Created user object for username: {}", username),
            "user_object_created",
            "new"
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
        Log::event(
            "DEBUG",
            "User Management",
            "Starting password hashing",
            "password_hash_start",
            "hash_password"
        );
        
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Password hashing failed - this indicates a serious system error")
            .to_string();

        Log::event(
            "DEBUG",
            "User Management",
            "Password hash generated successfully",
            "password_hash_success",
            "hash_password"
        );
        
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
        // Create span for password verification
        let span = db_operation_span("verify_password", "users.auth");
        span.record("username", &self.username);
        
        span.in_scope(|| {
            Log::event(
                "DEBUG",
                "User Management",
                "Starting password verification",
                "password_verify_start",
                "verify_password"
            );

            // Parse the stored hash
            let parsed_hash = match PasswordHash::new(&self.password_hash) {
                Ok(hash) => hash,
                Err(e) => {
                    span.record("result", &"hash_parse_error");
                    span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "User Management",
                        &format!("Failed to parse password hash: {}", e),
                        "password_hash_parse_error",
                        "verify_password"
                    );
                    
                    return Err(e.into());
                }
            };

            // Verify the password
            let is_verified = Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok();

            if is_verified {
                span.record("result", &"match");
                Log::event(
                    "DEBUG",
                    "User Management",
                    "Password verification successful",
                    "password_verify_success",
                    "verify_password"
                );
            } else {
                span.record("result", &"mismatch");
                Log::event(
                    "DEBUG",
                    "User Management",
                    "Password verification failed",
                    "password_verify_failure",
                    "verify_password"
                );
            }

            Ok(is_verified)
        })
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
        // Create span for save operation
        let span = db_operation_span("save_user", "users");
        span.record("username", &self.username);
        span.record("email_domain", &self.email.split('@').nth(1).unwrap_or("invalid"));
        
        user::record_create_attempt();
        
        Log::event(
            "DEBUG",
            "User Management",
            &format!("Saving user to database: {}", self.username),
            "user_save_start",
            "save"
        );

        // Use the span to wrap the database operation
        let result = span.in_scope(|| {
            conn.transaction(|conn| {
                diesel::insert_into(users::table)
                    .values(self)
                    .execute(conn)
            }).map_err(|e| {
                user::record_create_failure("query_error");
                span.record("db.success", &false);
                span.record_error(&e);
                
                Log::event(
                    "ERROR",
                    "User Management",
                    &format!("Failed to save user {}: {}", self.username, e),
                    "user_save_error",
                    "save"
                );
                
                // Convert to AuthServiceError explicitly
                AuthServiceError::Database(DatabaseError::Query {
                    source: e,
                    span: SpanTrace::capture(),
                })
            })
        });

        match &result {
            Ok(_) => {
                user::record_create_success();
                span.record("db.success", &true);
                
                Log::event(
                    "INFO",
                    "User Management",
                    &format!("User {} saved successfully", self.username),
                    "user_save_success",
                    "save"
                );
            }
            Err(_) => {} // Already handled in the error mapping
        }

        result
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
        // Create span for find_by_username operation
        let span = db_operation_span("find_user", "users.by_username");
        span.record("username", &username_str);
        
        user::record_lookup_username_attempt();
        
        Log::event(
            "DEBUG",
            "User Management",
            &format!("Searching for user by username: {}", username_str),
            "find_by_username_start",
            "find_by_username"
        );

        // Use the span to wrap the database operation
        let result = span.in_scope(|| {
            use crate::db::schema::users::dsl::*;
            
            users
                .filter(username.eq(username_str))
                .first::<User>(conn) // Explicit type annotation
                .map_err(|e| {
                    match e {
                        diesel::result::Error::NotFound => {
                            user::record_lookup_username_failure("not_found");
                            span.record("db.success", &false);
                            span.record("result", &"not_found");
                            
                            Log::event(
                                "DEBUG",
                                "User Management",
                                &format!("User not found by username: {}", username_str),
                                "find_by_username_not_found",
                                "find_by_username"
                            );
                        }
                        _ => {
                            user::record_lookup_username_failure("query_error");
                            span.record("db.success", &false);
                            span.record("result", &"error");
                            span.record_error(&e);
                            
                            Log::event(
                                "ERROR",
                                "User Management",
                                &format!("Database error finding user by username {}: {}", username_str, e),
                                "find_by_username_error",
                                "find_by_username"
                            );
                        }
                    }
                    // Convert to AuthServiceError explicitly
                    AuthServiceError::Database(DatabaseError::Query {
                        source: e,
                        span: SpanTrace::capture(),
                    })
                })
        });

        match &result {
            Ok(_) => {
                user::record_lookup_username_success();
                span.record("db.success", &true);
                span.record("result", &"success");
                
                Log::event(
                    "INFO",
                    "User Management",
                    &format!("User found by username: {}", username_str),
                    "find_by_username_success",
                    "find_by_username"
                );
            }
            Err(_) => {} // Already handled in the error mapping
        }

        result
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
        // Create span for find_by_email operation
        let span = db_operation_span("find_user", "users.by_email");
        span.record("email_domain", &email_str.split('@').nth(1).unwrap_or("invalid"));
        
        user::record_lookup_email_attempt();
        
        Log::event(
            "DEBUG",
            "User Management",
            &format!("Searching for user by email: {}", email_str),
            "find_by_email_start",
            "find_by_email"
        );

        // Use the span to wrap the database operation
        let result = span.in_scope(|| {
            use crate::db::schema::users::dsl::*;
            
            users
                .filter(email.eq(email_str))
                .first::<User>(conn) // Add explicit type annotation here
                .map_err(|e| {
                    match e {
                        diesel::result::Error::NotFound => {
                            user::record_lookup_email_failure("not_found");
                            span.record("db.success", &false);
                            span.record("result", &"not_found");
                            
                            Log::event(
                                "DEBUG",
                                "User Management",
                                &format!("User not found by email: {}", email_str),
                                "find_by_email_not_found",
                                "find_by_email"
                            );
                        }
                        _ => {
                            user::record_lookup_email_failure("query_error");
                            span.record("db.success", &false);
                            span.record("result", &"error");
                            span.record_error(&e);
                            
                            Log::event(
                                "ERROR",
                                "User Management",
                                &format!("Database error finding user by email {}: {}", email_str, e),
                                "find_by_email_error",
                                "find_by_email"
                            );
                        }
                    }
                    // Convert to AuthServiceError explicitly
                    AuthServiceError::Database(DatabaseError::Query {
                        source: e,
                        span: SpanTrace::capture(),
                    })
                })
        });

        match &result {
            Ok(_) => {
                user::record_lookup_email_success();
                span.record("db.success", &true);
                span.record("result", &"success");
                
                Log::event(
                    "INFO",
                    "User Management",
                    &format!("User found by email: {}", email_str),
                    "find_by_email_success",
                    "find_by_email"
                );
            }
            Err(_) => {} // Already handled in the error mapping
        }

        result
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
        // Create span for account activation
        let span = db_operation_span("activate_account", "users");
        span.record("email_domain", &self.email.split('@').nth(1).unwrap_or("invalid"));
        
        user::record_activate_attempt();
        
        Log::event(
            "DEBUG",
            "User Management",
            &format!("Activating account for user: {}", self.email),
            "user_activate_start",
            "activate"
        );

        // Use the span to wrap the database operation
        span.in_scope(|| {
            use crate::db::schema::users::dsl::*;
            
            diesel::update(users.filter(email.eq(&self.email)))
                .set(is_active.eq(true))
                .execute(conn)
                .map_err(|e| {
                    user::record_activate_failure("query_error");
                    span.record("db.success", &false);
                    span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "User Management",
                        &format!("Failed to activate account for {}: {}", self.email, e),
                        "user_activate_error",
                        "activate"
                    );
                    
                    // Convert to AuthServiceError explicitly
                    AuthServiceError::Database(DatabaseError::Query {
                        source: e,
                        span: SpanTrace::capture(),
                    })
                })?;

            user::record_activate_success();
            span.record("db.success", &true);
            span.record("result", &"success");
            
            Log::event(
                "INFO",
                "User Management",
                &format!("Account activated successfully for: {}", self.email),
                "user_activate_success",
                "activate"
            );

            Ok(())
        })
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
        // Create span for user update
        let span = db_operation_span("update_user", "users");
        span.record("username", &self.username);
        
        user::record_update_attempt();
        
        Log::event(
            "DEBUG",
            "User Management",
            &format!("Updating user record: {}", self.username),
            "user_update_start",
            "update"
        );

        // Get user ID first with error handling
        let user_id = self.id.ok_or_else(|| {
            user::record_update_failure("no_id");
            span.record("db.success", &false);
            span.record("failure_reason", &"missing_id");
            
            Log::event(
                "WARN",
                "User Management",
                &format!("Attempted to update user {} without ID", self.username),
                "user_update_no_id",
                "update"
            );
            
            AuthServiceError::Database(DatabaseError::Query {
                source: diesel::result::Error::NotFound,
                span: SpanTrace::capture(),
            })
        })?;

        // Use the span to wrap the database operation
        span.in_scope(|| {
            use crate::db::schema::users::dsl::*;
            
            diesel::update(users.filter(id.eq(user_id)))
                .set(self)
                .execute(conn)
                .map_err(|e| {
                    user::record_update_failure("query_error");
                    span.record("db.success", &false);
                    span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "User Management",
                        &format!("Failed to update user {}: {}", self.username, e),
                        "user_update_error",
                        "update"
                    );
                    
                    // Convert to AuthServiceError explicitly
                    AuthServiceError::Database(DatabaseError::Query {
                        source: e,
                        span: SpanTrace::capture(),
                    })
                })?;

            user::record_update_success();
            span.record("db.success", &true);
            span.record("result", &"success");
            
            Log::event(
                "INFO",
                "User Management",
                &format!("User {} updated successfully", self.username),
                "user_update_success",
                "update"
            );

            Ok(())
        })
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
        // Create span for password update
        let span = db_operation_span("update_password", "users");
        span.record("username", &self.username);
        
        user::record_password_update_attempt();
        
        Log::event(
            "DEBUG",
            "User Management",
            &format!("Updating password for user: {}", self.username),
            "password_update_start",
            "set_password_and_update"
        );

        // Use the span to wrap all operations
        span.in_scope(|| {
            // Hash the new password
            self.password_hash = User::hash_password(new_password);

            // If we don't yet have an id, fetch it from the DB
            if self.id.is_none() {
                span.record("needs_id_lookup", &true);
                match User::find_by_username(conn, &self.username) {
                    Ok(persisted) => {
                        self.id = persisted.id;
                    }
                    Err(e) => {
                        span.record("db.success", &false);
                        span.record("failure_reason", &"id_lookup_failed");
                        span.record_error(&e);
                        
                        Log::event(
                            "ERROR",
                            "User Management",
                            &format!("Failed to lookup user ID for {}: {}", self.username, e),
                            "password_update_id_lookup_failed",
                            "set_password_and_update"
                        );
                        
                        return Err(e);
                    }
                }
            }

            // Now safe to call update
            match self.update(conn) {
                Ok(_) => {
                    user::record_password_update_success();
                    span.record("db.success", &true);
                    span.record("result", &"success");
                    
                    Log::event(
                        "INFO",
                        "User Management",
                        &format!("Password updated successfully for user: {}", self.username),
                        "password_update_success",
                        "set_password_and_update"
                    );
                    
                    Ok(())
                }
                Err(e) => {
                    user::record_password_update_failure("update_failed");
                    span.record("db.success", &false);
                    span.record("failure_reason", &"update_failed");
                    span.record_error(&e);
                    
                    Log::event(
                        "ERROR",
                        "User Management",
                        &format!("Failed to update password for user {}: {}", self.username, e),
                        "password_update_failed",
                        "set_password_and_update"
                    );
                    
                    Err(e)
                }
            }
        })
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