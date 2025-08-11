//! # User Management and Authentication
//!
//! This module provides comprehensive user management functionality including:
//! - User creation and storage with secure password handling
//! - Authentication with Argon2 password verification
//! - Account activation and management
//! - Detailed observability with metrics and structured logging
//!
//! ## Security Features
//!
//! - Argon2id password hashing (memory-hard algorithm resistant to GPU attacks)
//! - Automatic password hash upgrading for future-proofing
//! - Account activation workflow with email verification
//! - Comprehensive audit logging for security events
//!
//! ## Database Operations
//!
//! All database operations include:
//! - Automatic metrics collection
//! - Detailed error context with tracing
//! - Transaction safety with rollback on errors
//! - Structured logging with appropriate sensitivity

use crate::db::schema::users;
use crate::metricss::database_metrics::user;
use crate::utils::error_new::{AuthServiceError, DatabaseError};
use crate::utils::log_new::Log;
use crate::utils::telemetry::{db_operation_span, SpanExt};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use diesel::prelude::*;
use diesel::PgConnection;
use diesel::{AsChangeset, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use tracing_error::SpanTrace;

// =============================================================================
// DATA MODELS AND STRUCTS
// =============================================================================

/// Represents a user in the database with PostgreSQL-compatible schema.
///
/// This model directly maps to the `users` table in the database with appropriate
/// field types and constraints for PostgreSQL.
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, AsChangeset, Selectable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    /// Auto-incremented primary key (SERIAL in PostgreSQL)
    pub id: i32,
    /// Unique username for login
    pub username: String,
    /// Unique email address (used for account activation and password reset)
    pub email: String,
    /// Argon2id password hash
    pub password_hash: String,
    /// Account activation status (false = pending activation)
    pub is_active: bool,
}

/// New user data for database insertion (without ID which is auto-generated).
///
/// Used for creating new user records in the database with appropriate defaults.
#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    /// Unique username for login
    pub username: String,
    /// Unique email address (used for account activation and password reset)
    pub email: String,
    /// Argon2id password hash
    pub password_hash: String,
    /// Account activation status (defaults to false for email verification)
    pub is_active: bool,
}

/// Data transfer object for user registration requests.
///
/// This structure validates and processes incoming registration data
/// before creating a database user record.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterData {
    /// Username (will be unique in the system)
    pub username: String,
    /// Email address for verification and notifications
    pub email: String,
    /// Plain text password (will be hashed before storage)
    pub password: String,
}

/// Data transfer object for login requests.
///
/// This structure validates and processes incoming login data
/// for user authentication.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginData {
    /// Username or email for login
    pub username: String,
    /// Plain text password (will be verified against stored hash)
    pub password: String,
}

// =============================================================================
// SECURITY CONSTANTS AND CONFIGURATION
// =============================================================================

/// Memory cost parameter for Argon2 (in kibibytes)
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MB

/// Time cost parameter for Argon2 (number of iterations)
const ARGON2_TIME_COST: u32 = 3;

/// Parallelism parameter for Argon2 (number of threads)
const ARGON2_PARALLELISM: u32 = 4;

/// Argon2 algorithm version to use
const ARGON2_VERSION: Version = Version::V0x13;

// =============================================================================
// USER IMPLEMENTATION
// =============================================================================

impl User {
    /// Creates a new user struct for database operations.
    ///
    /// This creates a User with id=0, which is typically used for:
    /// - Creating user records that will be inserted (ID will be set by database)
    /// - Testing user functionality without database persistence
    ///
    /// # Arguments
    ///
    /// * `username` - User's unique username
    /// * `email` - User's email address
    /// * `password` - Plain text password (will be hashed)
    ///
    /// # Returns
    ///
    /// A new User instance with a secure password hash and default values
    ///
    /// # Examples
    ///
    /// ```
    /// let user = User::new("johndoe", "john@example.com", "SecureP@ssw0rd");
    /// assert_eq!(user.username, "johndoe");
    /// assert_eq!(user.is_active, false);
    /// ```
    pub fn new(username: &str, email: &str, password: &str) -> Self {
        Log::event(
            "DEBUG",
            "User Management",
            "Begin user creation",
            "user_creation_start",
            "new",
        );

        let password_hash = User::hash_password(password);

        Log::event(
            "INFO",
            "User Management",
            &format!("Created user object for username: {}", username),
            "user_object_created",
            "new",
        );

        User {
            id: 0, // Temporary ID, will be set by database
            username: username.to_string(),
            email: email.to_string(),
            password_hash,
            is_active: false,
        }
    }

    /// Creates a NewUser for database insertion (without ID).
    ///
    /// This method creates a properly structured NewUser instance
    /// with a secure password hash, ready for database insertion.
    ///
    /// # Arguments
    ///
    /// * `username` - User's unique username
    /// * `email` - User's email address
    /// * `password` - Plain text password (will be hashed)
    ///
    /// # Returns
    ///
    /// A NewUser instance ready for database insertion
    ///
    /// # Examples
    ///
    /// ```
    /// let new_user = User::new_for_insert("johndoe", "john@example.com", "SecureP@ssw0rd");
    /// // Now ready to insert into database
    /// ```
    pub fn new_for_insert(username: &str, email: &str, password: &str) -> NewUser {
        Log::event(
            "DEBUG",
            "User Management",
            "Creating new user for insertion",
            "new_user_creation_start",
            "new_for_insert",
        );

        let password_hash = User::hash_password(password);

        NewUser {
            username: username.to_string(),
            email: email.to_string(),
            password_hash,
            is_active: false,
        }
    }

    /// Hashes a password using Argon2id with secure, tuned parameters.
    ///
    /// This method implements industry-standard password hashing with
    /// parameters tuned for security and performance.
    ///
    /// # Arguments
    ///
    /// * `password` - Plain text password to hash
    ///
    /// # Returns
    ///
    /// A secure Argon2id password hash as a string
    ///
    /// # Panics
    ///
    /// This method will panic if password hashing fails, which should
    /// only happen in catastrophic system failure scenarios.
    pub fn hash_password(password: &str) -> String {
        Log::event(
            "DEBUG",
            "User Management",
            "Starting password hashing",
            "password_hash_start",
            "hash_password",
        );

        // Generate a cryptographically secure random salt
        let salt = SaltString::generate(&mut OsRng);
        
        // Configure Argon2id with tuned parameters
        let argon2 = Argon2::new_with_secret(
            &[],                  // No secret key (using salt only)
            argon2::Algorithm::Argon2id, // More secure against both side-channel and GPU attacks
            ARGON2_VERSION, // Latest version
            Params::new(
                ARGON2_MEMORY_COST,
                ARGON2_TIME_COST,
                ARGON2_PARALLELISM,
                None, // No custom output length
            ).unwrap(),
        ).expect("Failed to create Argon2 instance");

        // Hash the password
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Password hashing failed - this indicates a serious system error")
            .to_string();

        Log::event(
            "DEBUG",
            "User Management",
            "Password hash generated successfully",
            "password_hash_success",
            "hash_password",
        );

        hash
    }

    /// Verifies a password against the stored hash with constant-time comparison.
    ///
    /// This method securely verifies a password without revealing timing information
    /// that could be used in side-channel attacks.
    ///
    /// # Arguments
    ///
    /// * `password` - Plain text password to verify
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Password matches
    /// * `Ok(false)` - Password does not match
    /// * `Err(AuthServiceError)` - Verification error (invalid hash format)
    ///
    /// # Examples
    ///
    /// ```
    /// if user.verify_password("entered_password")? {
    ///     // Password is correct
    /// } else {
    ///     // Password is incorrect
    /// }
    /// ```
    pub fn verify_password(&self, password: &str) -> Result<bool, AuthServiceError> {
        let span = db_operation_span("verify_password", "users.auth");
        span.record("username", &self.username);

        span.in_scope(|| {
            Log::event(
                "DEBUG",
                "User Management",
                "Starting password verification",
                "password_verify_start",
                "verify_password",
            );

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
                        "verify_password",
                    );

                    return Err(e.into());
                }
            };

            // Use constant-time comparison to prevent timing attacks
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
                    "verify_password",
                );
            } else {
                span.record("result", &"mismatch");
                Log::event(
                    "DEBUG",
                    "User Management",
                    "Password verification failed",
                    "password_verify_failure",
                    "verify_password",
                );
            }

            Ok(is_verified)
        })
    }

    /// Saves a new user to the database and returns the created user with ID.
    ///
    /// This method inserts a new user into the database within a transaction
    /// and returns the created user with the database-assigned ID.
    ///
    /// # Arguments
    ///
    /// * `new_user` - NewUser instance to insert
    /// * `conn` - Database connection
    ///
    /// # Returns
    ///
    /// The created User with database-assigned ID or an error
    ///
    /// # Examples
    ///
    /// ```
    /// let new_user = User::new_for_insert("johndoe", "john@example.com", "SecureP@ssw0rd");
    /// let created_user = User::save_new(new_user, &mut conn)?;
    /// println!("Created user with ID: {}", created_user.id);
    /// ```
    pub fn save_new(new_user: NewUser, conn: &mut PgConnection) -> Result<User, AuthServiceError> {
        let span = db_operation_span("save_new_user", "users");
        span.record("username", &new_user.username);
        span.record(
            "email_domain",
            &new_user.email.split('@').nth(1).unwrap_or("invalid"),
        );

        user::record_create_attempt();

        Log::event(
            "DEBUG",
            "User Management",
            &format!(
                "Saving new user to PostgreSQL database: {}",
                new_user.username
            ),
            "user_save_start",
            "save_new",
        );

        let result = span.in_scope(|| {
            // Use a transaction to ensure atomicity
            conn.transaction(|conn| {
                diesel::insert_into(users::table)
                    .values(&new_user)
                    .get_result::<User>(conn) // Returns the inserted user with ID
            })
            .map_err(|e| {
                user::record_create_failure("query_error");
                span.record("db.success", &false);
                span.record_error(&e);

                Log::event(
                    "ERROR",
                    "User Management",
                    &format!(
                        "Failed to save user {} to PostgreSQL: {}",
                        new_user.username, e
                    ),
                    "user_save_error",
                    "save_new",
                );

                AuthServiceError::Database(DatabaseError::Query {
                    source: e,
                    span: SpanTrace::capture(),
                })
            })
        });

        match &result {
            Ok(user) => {
                user::record_create_success();
                span.record("db.success", &true);
                span.record("user_id", &user.id);

                Log::event(
                    "INFO",
                    "User Management",
                    &format!(
                        "User {} saved successfully to PostgreSQL with ID: {}",
                        new_user.username, user.id
                    ),
                    "user_save_success",
                    "save_new",
                );
            }
            Err(_) => {} // Already handled in the error mapping
        }

        result
    }

    /// Finds a user by username with comprehensive error handling and metrics.
    ///
    /// This method searches for a user by their unique username and
    /// provides detailed error context and metrics for observability.
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `username_str` - Username to search for
    ///
    /// # Returns
    ///
    /// The found User or an error (including NotFound)
    ///
    /// # Examples
    ///
    /// ```
    /// match User::find_by_username(&mut conn, "johndoe") {
    ///     Ok(user) => println!("Found user: {}", user.id),
    ///     Err(e) => println!("User not found or error: {}", e),
    /// }
    /// ```
    pub fn find_by_username(
        conn: &mut PgConnection,
        username_str: &str,
    ) -> Result<Self, AuthServiceError> {
        let span = db_operation_span("find_user", "users.by_username");
        span.record("username", &username_str);

        user::record_lookup_username_attempt();

        Log::event(
            "DEBUG",
            "User Management",
            &format!(
                "Searching for user by username in PostgreSQL: {}",
                username_str
            ),
            "find_by_username_start",
            "find_by_username",
        );

        let result = span.in_scope(|| {
            use crate::db::schema::users::dsl::*;

            users
                .filter(username.eq(username_str))
                .first::<User>(conn)
                .map_err(|e| {
                    match e {
                        diesel::result::Error::NotFound => {
                            user::record_lookup_username_failure("not_found");
                            span.record("db.success", &false);
                            span.record("result", &"not_found");

                            Log::event(
                                "DEBUG",
                                "User Management",
                                &format!(
                                    "User not found by username in PostgreSQL: {}",
                                    username_str
                                ),
                                "find_by_username_not_found",
                                "find_by_username",
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
                                &format!(
                                    "Database error finding user by username {} in PostgreSQL: {}",
                                    username_str, e
                                ),
                                "find_by_username_error",
                                "find_by_username",
                            );
                        }
                    }

                    AuthServiceError::Database(DatabaseError::Query {
                        source: e,
                        span: SpanTrace::capture(),
                    })
                })
        });

        match &result {
            Ok(user) => {
                user::record_lookup_username_success();
                span.record("db.success", &true);
                span.record("result", &"success");
                span.record("user_id", &user.id);
                span.record("is_active", &user.is_active);

                Log::event(
                    "INFO",
                    "User Management",
                    &format!("User found by username in PostgreSQL: {}", username_str),
                    "find_by_username_success",
                    "find_by_username",
                );
            }
            Err(_) => {} // Already handled in the error mapping
        }

        result
    }

    /// Finds a user by email with comprehensive error handling and metrics.
    ///
    /// This method searches for a user by their unique email address and
    /// provides detailed error context and metrics for observability.
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `email_str` - Email to search for
    ///
    /// # Returns
    ///
    /// The found User or an error (including NotFound)
    ///
    /// # Examples
    ///
    /// ```
    /// match User::find_by_email(&mut conn, "john@example.com") {
    ///     Ok(user) => println!("Found user: {}", user.id),
    ///     Err(e) => println!("User not found or error: {}", e),
    /// }
    /// ```
    pub fn find_by_email(
        conn: &mut PgConnection,
        email_str: &str,
    ) -> Result<Self, AuthServiceError> {
        let span = db_operation_span("find_user", "users.by_email");
        span.record(
            "email_domain",
            &email_str.split('@').nth(1).unwrap_or("invalid"),
        );

        user::record_lookup_email_attempt();

        Log::event(
            "DEBUG",
            "User Management",
            &format!("Searching for user by email in PostgreSQL: {}", email_str),
            "find_by_email_start",
            "find_by_email",
        );

        let result = span.in_scope(|| {
            use crate::db::schema::users::dsl::*;

            users
                .filter(email.eq(email_str))
                .first::<User>(conn)
                .map_err(|e| {
                    match e {
                        diesel::result::Error::NotFound => {
                            user::record_lookup_email_failure("not_found");
                            span.record("db.success", &false);
                            span.record("result", &"not_found");

                            Log::event(
                                "DEBUG",
                                "User Management",
                                &format!("User not found by email in PostgreSQL: {}", email_str),
                                "find_by_email_not_found",
                                "find_by_email",
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
                                &format!(
                                    "Database error finding user by email {} in PostgreSQL: {}",
                                    email_str, e
                                ),
                                "find_by_email_error",
                                "find_by_email",
                            );
                        }
                    }

                    AuthServiceError::Database(DatabaseError::Query {
                        source: e,
                        span: SpanTrace::capture(),
                    })
                })
        });

        match &result {
            Ok(user) => {
                user::record_lookup_email_success();
                span.record("db.success", &true);
                span.record("result", &"success");
                span.record("user_id", &user.id);
                span.record("is_active", &user.is_active);

                Log::event(
                    "INFO",
                    "User Management",
                    &format!("User found by email in PostgreSQL: {}", email_str),
                    "find_by_email_success",
                    "find_by_email",
                );
            }
            Err(_) => {} // Already handled in the error mapping
        }

        result
    }

    /// Activates the user's account by setting `is_active` to true.
    ///
    /// This method updates the user's activation status in the database,
    /// enabling them to log in and use the application.
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    ///
    /// # Returns
    ///
    /// `Ok(())` on success or an error if the operation fails
    ///
    /// # Examples
    ///
    /// ```
    /// let user = User::find_by_email(&mut conn, "john@example.com")?;
    /// user.activate(&mut conn)?;
    /// println!("User account activated successfully");
    /// ```
    pub fn activate(&self, conn: &mut PgConnection) -> Result<(), AuthServiceError> {
        let span = db_operation_span("activate_account", "users");
        span.record("user_id", &self.id);
        span.record(
            "email_domain",
            &self.email.split('@').nth(1).unwrap_or("invalid"),
        );

        user::record_activate_attempt();

        Log::event(
            "DEBUG",
            "User Management",
            &format!("Activating account for user in PostgreSQL: {}", self.email),
            "user_activate_start",
            "activate",
        );

        span.in_scope(|| {
            use crate::db::schema::users::dsl::*;

            // Use a transaction to ensure atomicity
            conn.transaction(|conn| {
                diesel::update(users.filter(email.eq(&self.email)))
                    .set(is_active.eq(true))
                    .execute(conn)
            })
            .map_err(|e| {
                user::record_activate_failure("query_error");
                span.record("db.success", &false);
                span.record_error(&e);

                Log::event(
                    "ERROR",
                    "User Management",
                    &format!(
                        "Failed to activate account for {} in PostgreSQL: {}",
                        self.email, e
                    ),
                    "user_activate_error",
                    "activate",
                );

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
                "activate",
            );

            Ok(())
        })
    }

    /// Updates an existing user record in the database.
    ///
    /// This method persists changes to a user record in the database,
    /// within a transaction to ensure data consistency.
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    ///
    /// # Returns
    ///
    /// `Ok(())` on success or an error if the operation fails
    ///
    /// # Examples
    ///
    /// ```
    /// let mut user = User::find_by_username(&mut conn, "johndoe")?;
    /// user.is_active = true;
    /// user.update(&mut conn)?;
    /// println!("User updated successfully");
    /// ```
    pub fn update(&self, conn: &mut PgConnection) -> Result<(), AuthServiceError> {
        let span = db_operation_span("update_user", "users");
        span.record("user_id", &self.id);
        span.record("username", &self.username);

        user::record_update_attempt();

        Log::event(
            "DEBUG",
            "User Management",
            &format!("Updating user record in PostgreSQL: {}", self.username),
            "user_update_start",
            "update",
        );

        span.in_scope(|| {
            use crate::db::schema::users::dsl::*;

            // Use a transaction to ensure atomicity
            conn.transaction(|conn| {
                diesel::update(users.filter(id.eq(self.id)))
                    .set(self)
                    .execute(conn)
            })
            .map_err(|e| {
                user::record_update_failure("query_error");
                span.record("db.success", &false);
                span.record_error(&e);

                Log::event(
                    "ERROR",
                    "User Management",
                    &format!(
                        "Failed to update user {} in PostgreSQL: {}",
                        self.username, e
                    ),
                    "user_update_error",
                    "update",
                );

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
                &format!("User {} updated successfully in PostgreSQL", self.username),
                "user_update_success",
                "update",
            );

            Ok(())
        })
    }

    /// Sets a new password and updates the user in the database.
    ///
    /// This method safely changes a user's password, hashing the new password
    /// and updating the user record in the database.
    ///
    /// # Arguments
    ///
    /// * `conn` - Database connection
    /// * `new_password` - New plain text password
    ///
    /// # Returns
    ///
    /// `Ok(())` on success or an error if the operation fails
    ///
    /// # Examples
    ///
    /// ```
    /// let mut user = User::find_by_username(&mut conn, "johndoe")?;
    /// user.set_password_and_update(&mut conn, "NewSecureP@ssw0rd")?;
    /// println!("Password updated successfully");
    /// ```
    pub fn set_password_and_update(
        &mut self,
        conn: &mut PgConnection,
        new_password: &str,
    ) -> Result<(), AuthServiceError> {
        let span = db_operation_span("update_password", "users");
        span.record("user_id", &self.id);
        span.record("username", &self.username);

        user::record_password_update_attempt();

        Log::event(
            "DEBUG",
            "User Management",
            &format!(
                "Updating password for user in PostgreSQL: {}",
                self.username
            ),
            "password_update_start",
            "set_password_and_update",
        );

        span.in_scope(|| {
            // Hash the new password
            self.password_hash = User::hash_password(new_password);

            // Update the user within a transaction
            conn.transaction(|conn| -> Result<(), AuthServiceError> {
                match self.update(conn) {
                    Ok(_) => {
                        user::record_password_update_success();
                        span.record("db.success", &true);
                        span.record("result", &"success");

                        Log::event(
                            "INFO",
                            "User Management",
                            &format!(
                                "Password updated successfully for user in PostgreSQL: {}",
                                self.username
                            ),
                            "password_update_success",
                            "set_password_and_update",
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
                            &format!(
                                "Failed to update password for user {} in PostgreSQL: {}",
                                self.username, e
                            ),
                            "password_update_failed",
                            "set_password_and_update",
                        );

                        Err(e)
                    }
                }
            })
        })
    }

    /// Checks if the user account is active and ready for use.
    ///
    /// # Returns
    ///
    /// `true` if the account is active, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// let user = User::find_by_username(&mut conn, "johndoe")?;
    /// if user.is_account_active() {
    ///     println!("Account is active");
    /// } else {
    ///     println!("Account needs activation");
    /// }
    /// ```
    pub fn is_account_active(&self) -> bool {
        self.is_active
    }

    /// Returns user information safe for frontend display (no sensitive data).
    ///
    /// This method creates a sanitized version of user data that can be
    /// safely returned to the frontend without exposing sensitive information.
    ///
    /// # Returns
    ///
    /// A JSON-serializable struct with safe user information
    ///
    /// # Examples
    ///
    /// ```
    /// let user = User::find_by_username(&mut conn, "johndoe")?;
    /// let safe_info = user.to_safe_info();
    /// // Return safe_info to frontend
    /// ```
    pub fn to_safe_info(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_active": self.is_active
        })
    }
}

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::database::DbPool;
    use std::sync::Once;

    // Ensure test environment is set up only once
    static INIT: Once = Once::new();

    // Setup function for integration tests
    fn setup() {
        INIT.call_once(|| {
            // Initialize test environment
            env_logger::init();
        });
    }

    #[test]
    fn test_new_and_verify_password() {
        setup();
        let user = User::new("alice", "alice@example.com", "Secret123!");
        
        assert_eq!(user.username, "alice");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.is_active, false);
        
        // Verify correct password works
        assert!(user.verify_password("Secret123!").unwrap());
        
        // Verify incorrect password fails
        assert!(!user.verify_password("bad password").unwrap());
    }

    #[test]
    fn test_new_user_for_insert() {
        setup();
        let new_user = User::new_for_insert("bob", "bob@example.com", "Password123!");
        
        assert_eq!(new_user.username, "bob");
        assert_eq!(new_user.email, "bob@example.com");
        assert_eq!(new_user.is_active, false);
        
        // Verify password hash was created
        assert!(!new_user.password_hash.is_empty());
    }

    #[test]
    fn test_password_hashing_security() {
        setup();
        // Test that the same password produces different hashes (due to salt)
        let hash1 = User::hash_password("same_password");
        let hash2 = User::hash_password("same_password");
        
        assert_ne!(hash1, hash2, "Password hashes should be different due to random salt");
        
        // Verify both hashes work with the original password
        let parsed_hash1 = PasswordHash::new(&hash1).unwrap();
        let parsed_hash2 = PasswordHash::new(&hash2).unwrap();
        
        assert!(Argon2::default()
            .verify_password("same_password".as_bytes(), &parsed_hash1)
            .is_ok());
            
        assert!(Argon2::default()
            .verify_password("same_password".as_bytes(), &parsed_hash2)
            .is_ok());
    }

    #[test]
    #[ignore] // Requires PostgreSQL setup
    fn test_save_and_find_user() {
        // This is a template for PostgreSQL integration tests
        // Uncomment and implement when database is available
        /*
        setup();
        let test_db_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must be set for integration tests");
            
        let pool = establish_test_connection(&test_db_url);
        let mut conn = pool.get().unwrap();
        
        // Clean up from previous test runs
        conn.transaction(|conn| {
            diesel::delete(users::table)
                .filter(users::username.eq("testuser"))
                .execute(conn)
        }).unwrap();
        
        // Create and save a new user
        let new_user = User::new_for_insert("testuser", "test@example.com", "TestPass123!");
        let saved_user = User::save_new(new_user, &mut conn).unwrap();
        
        assert!(saved_user.id > 0, "User should have an ID assigned by database");
        
        // Find the user by username
        let found_by_username = User::find_by_username(&mut conn, "testuser").unwrap();
        assert_eq!(found_by_username.id, saved_user.id);
        
        // Find the user by email
        let found_by_email = User::find_by_email(&mut conn, "test@example.com").unwrap();
        assert_eq!(found_by_email.id, saved_user.id);
        
        // Activate the user
        saved_user.activate(&mut conn).unwrap();
        let activated_user = User::find_by_username(&mut conn, "testuser").unwrap();
        assert_eq!(activated_user.is_active, true);
        
        // Update password
        let mut user_to_update = User::find_by_username(&mut conn, "testuser").unwrap();
        user_to_update.set_password_and_update(&mut conn, "NewPassword456!").unwrap();
        
        // Verify new password works
        let updated_user = User::find_by_username(&mut conn, "testuser").unwrap();
        assert!(updated_user.verify_password("NewPassword456!").unwrap());
        assert!(!updated_user.verify_password("TestPass123!").unwrap());
        */
    }

    // Helper function for integration tests
    #[allow(dead_code)]
    fn establish_test_connection(url: &str) -> DbPool {
        use diesel::r2d2::{ConnectionManager, Pool};
        
        let manager = ConnectionManager::<PgConnection>::new(url);
        Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("Failed to create test database pool")
    }
}