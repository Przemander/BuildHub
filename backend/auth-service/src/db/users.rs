//! User database model and data access layer.
//!
//! Implements secure password handling with Argon2id and provides a clean,
//! transactional API for all user-related database operations. This module
//! is completely decoupled from the HTTP layer.

use crate::{
    db::schema::users,
    utils::{errors::AuthServiceError, hashing, metrics},
};
use diesel::prelude::*;
use diesel::{AsChangeset, Identifiable, Insertable, PgConnection, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument, warn};

// =============================================================================
// DATA MODELS
// =============================================================================

/// Represents a user record from the `users` table.
/// This is the primary struct for user data retrieved from the database.
#[derive(
    Debug, Serialize, Deserialize, Queryable, Insertable, AsChangeset, Selectable, Clone, Identifiable,
)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
}

/// Represents a new user to be inserted into the database.
/// This struct is used for the `INSERT` operation.
#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
}

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl User {
    /// Creates a `NewUser` struct, ready for database insertion.
    /// The password is automatically hashed using Argon2id.
    pub fn new_for_insert(username: &str, email: &str, password: &str) -> NewUser {
        NewUser {
            username: username.to_string(),
            email: email.to_string(),
            password_hash: Self::hash_password(password),
            is_active: false,
        }
    }

    /// Hashes a password by delegating to the hashing utility.
    pub fn hash_password(password: &str) -> String {
        hashing::hash_password(password)
    }

    /// Verifies a password against the user's stored hash by delegating to the hashing utility.
    #[instrument(skip(self, password), name = "user_verify_password")]
    pub fn verify_password(&self, password: &str) -> Result<bool, AuthServiceError> {
        hashing::verify_password(password, &self.password_hash)
    }

    /// Saves a new user to the database within a transaction.
    /// Handles unique constraint violations for username and email.
    #[instrument(skip(new_user, conn), name = "db_save_user")]
    pub fn save_new(new_user: NewUser, conn: &mut PgConnection) -> Result<User, AuthServiceError> {
        let result = conn.transaction(|conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .get_result::<User>(conn)
        });

        match result {
            Ok(user) => {
                metrics::db::query_success("user_create");
                info!(user_id = %user.id, "User {} created successfully", user.username);
                Ok(user)
            }
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                info,
            )) => {
                metrics::db::query_failure("user_create");
                if let Some(constraint) = info.constraint_name() {
                    if constraint.contains("email") {
                        return Err(AuthServiceError::validation("email", "Email already registered"));
                    } else if constraint.contains("username") {
                        return Err(AuthServiceError::validation("username", "Username already taken"));
                    }
                }
                Err(AuthServiceError::database("Failed to create user due to constraint violation"))
            }
            Err(e) => {
                error!("Database error when creating user: {}", e);
                metrics::db::query_failure("user_create");
                Err(AuthServiceError::database("Failed to create user"))
            }
        }
    }

    /// Finds a user by their username.
    #[instrument(skip(conn), name = "db_find_user_by_username")]
    pub fn find_by_username(
        conn: &mut PgConnection,
        username_str: &str,
    ) -> Result<Self, AuthServiceError> {
        use crate::db::schema::users::dsl::*;

        users
            .filter(username.eq(username_str))
            .first::<User>(conn)
            .map_err(|e| {
                match e {
                    diesel::result::Error::NotFound => {
                        warn!("User lookup failed: username '{}' not found", username_str);
                        metrics::db::query_failure("user_lookup_username_not_found");
                        AuthServiceError::authentication("Invalid credentials")
                    }
                    _ => {
                        error!("Database error finding user {}: {}", username_str, e);
                        metrics::db::query_failure("user_lookup_username_error");
                        AuthServiceError::database("Failed to find user")
                    }
                }
            })
            .map(|user| {
                metrics::db::query_success("user_lookup_username");
                user
            })
    }

    /// Finds a user by their email address.
    #[instrument(skip(conn), name = "db_find_user_by_email")]
    pub fn find_by_email(
        conn: &mut PgConnection,
        email_str: &str,
    ) -> Result<Self, AuthServiceError> {
        use crate::db::schema::users::dsl::*;

        users
            .filter(email.eq(email_str))
            .first::<User>(conn)
            .map_err(|e| {
                match e {
                    diesel::result::Error::NotFound => {
                        warn!("User lookup failed: email '{}' not found", email_str);
                        metrics::db::query_failure("user_lookup_email_not_found");
                        AuthServiceError::authentication("Invalid credentials")
                    }
                    _ => {
                        error!("Database error finding user by email: {}", e);
                        metrics::db::query_failure("user_lookup_email_error");
                        AuthServiceError::database("Failed to find user")
                    }
                }
            })
            .map(|user| {
                metrics::db::query_success("user_lookup_email");
                user
            })
    }

    /// Activates the user's account in a transaction.
    #[instrument(skip(self, conn), name = "db_activate_user")]
    pub fn activate(&self, conn: &mut PgConnection) -> Result<(), AuthServiceError> {
        use crate::db::schema::users::dsl::*;

        let updated_rows = conn
            .transaction(|conn| {
                diesel::update(users.filter(id.eq(self.id)))
                    .set(is_active.eq(true))
                    .execute(conn)
            })
            .map_err(|e| {
                error!("Failed to activate account for {}: {}", self.email, e);
                metrics::db::query_failure("user_activate");
                AuthServiceError::database("Failed to activate account")
            })?;

        if updated_rows == 1 {
            metrics::db::query_success("user_activate");
            info!(user_id = %self.id, "Account activated for {}", self.email);
            Ok(())
        } else {
            error!(
                "Failed to activate account for {}: user not found or no change needed",
                self.email
            );
            metrics::db::query_failure("user_activate_no_effect");
            Err(AuthServiceError::database("Failed to activate account"))
        }
    }

    /// Updates the entire user record in a transaction.
    #[instrument(skip(self, conn), name = "db_update_user")]
    pub fn update(&self, conn: &mut PgConnection) -> Result<usize, AuthServiceError> {
        conn.transaction(|conn| diesel::update(self).set(self).execute(conn))
            .map_err(|e| {
                error!("Failed to update user {}: {}", self.username, e);
                metrics::db::query_failure("user_update");
                AuthServiceError::database("Failed to update user")
            })
            .map(|count| {
                metrics::db::query_success("user_update");
                count
            })
    }

    /// Sets a new password for the user and saves the change to the database.
    #[instrument(skip(self, conn, new_password), name = "db_set_password")]
    pub fn set_password_and_update(
        &mut self,
        conn: &mut PgConnection,
        new_password: &str,
    ) -> Result<(), AuthServiceError> {
        self.password_hash = Self::hash_password(new_password);
        self.update(conn)?;
        info!("Password updated for user {}", self.username);
        Ok(())
    }

    /// Returns safe, non-sensitive user information, suitable for sending to a client.
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
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let new_user = User::new_for_insert("alice", "alice@example.com", "Secret123!");
        let user = User {
            id: 1,
            username: new_user.username,
            email: new_user.email,
            password_hash: new_user.password_hash,
            is_active: new_user.is_active,
        };

        assert!(user.verify_password("Secret123!").unwrap());
        assert!(!user.verify_password("wrong").unwrap());
    }

    #[test]
    fn test_password_hash_uniqueness() {
        let hash1 = User::hash_password("password");
        let hash2 = User::hash_password("password");

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // Both should verify correctly using our utility function
        assert!(hashing::verify_password("password", &hash1).unwrap());
        assert!(hashing::verify_password("password", &hash2).unwrap());
    }

    #[test]
    fn test_new_user_for_insert() {
        let new_user = User::new_for_insert("bob", "bob@example.com", "Pass123!");

        assert_eq!(new_user.username, "bob");
        assert_eq!(new_user.email, "bob@example.com");
        assert!(!new_user.password_hash.is_empty());
        assert!(!new_user.is_active);
    }

    #[test]
    fn test_to_safe_info() {
        let user = User {
            id: 1,
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "some_hash_string".to_string(),
            is_active: true,
        };

        let info = user.to_safe_info();
        assert_eq!(info["id"], 1);
        assert_eq!(info["username"], "test");
        assert_eq!(info["email"], "test@example.com");
        assert_eq!(info["is_active"], true);
        assert!(info.get("password_hash").is_none());
    }

    #[test]
    fn test_password_verification_with_invalid_hash_format() {
        let user = User {
            id: 1,
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "this_is_not_a_valid_argon2_hash".to_string(),
            is_active: true,
        };

        // Should return an error for invalid hash format, not just `false`.
        let result = user.verify_password("Pass123!");
        assert!(result.is_err());
        assert!(matches!(result, Err(AuthServiceError::Internal(_))));
    }
}