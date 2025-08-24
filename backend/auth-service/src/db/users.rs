//! User management and authentication.
//!
//! Portfolio-ready with secure password handling, minimal overhead, and clean design.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use diesel::prelude::*;
use diesel::{AsChangeset, Insertable, PgConnection, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::db::schema::users;
use crate::metrics;
use crate::utils::errors::AuthServiceError;

// =============================================================================
// DATA MODELS
// =============================================================================

/// User model mapping to the database schema.
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, AsChangeset, Selectable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
}

/// New user for database insertion.
#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
}

/// Registration request data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterData {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Login request data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginData {
    pub username: String,
    pub password: String,
}

// =============================================================================
// SECURITY CONFIGURATION
// =============================================================================

const ARGON2_MEMORY_COST: u32 = 65536; // 64 MB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_VERSION: Version = Version::V0x13;

// =============================================================================
// IMPLEMENTATION
// =============================================================================

impl User {
    /// Creates a new user with hashed password.
    pub fn new(username: &str, email: &str, password: &str) -> Self {
        User {
            id: 0,
            username: username.to_string(),
            email: email.to_string(),
            password_hash: Self::hash_password(password),
            is_active: false,
        }
    }

    /// Creates a NewUser for database insertion.
    pub fn new_for_insert(username: &str, email: &str, password: &str) -> NewUser {
        NewUser {
            username: username.to_string(),
            email: email.to_string(),
            password_hash: Self::hash_password(password),
            is_active: false,
        }
    }

    /// Hashes a password using Argon2id.
    pub fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        
        let argon2 = Argon2::new_with_secret(
            &[],
            argon2::Algorithm::Argon2id,
            ARGON2_VERSION,
            Params::new(ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, None).unwrap(),
        ).expect("Failed to create Argon2 instance");

        argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Password hashing failed")
            .to_string()
    }

    /// Verifies a password against the stored hash.
    pub fn verify_password(&self, password: &str) -> Result<bool, AuthServiceError> {
        let parsed_hash = PasswordHash::new(&self.password_hash)
            .map_err(|e| AuthServiceError::internal(format!("Invalid password hash: {}", e)))?;
        
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Saves a new user to the database.
    pub fn save_new(new_user: NewUser, conn: &mut PgConnection) -> Result<User, AuthServiceError> {
        let result = conn.transaction(|conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .get_result::<User>(conn)
        })
        .map_err(|e| {
            error!("Failed to save user {}: {}", new_user.username, e);
            metrics::db::query_failure("user_create");
            
            // Check for unique constraint violations
            if let diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                info,
            ) = &e {
                if let Some(constraint) = info.constraint_name() {
                    if constraint.contains("email") {
                        return AuthServiceError::validation("email", "Email already registered");
                    } else if constraint.contains("username") {
                        return AuthServiceError::validation("username", "Username already taken");
                    }
                }
            }
            
            AuthServiceError::database("Failed to create user")
        })?;

        metrics::db::query_success("user_create");
        info!("User {} created successfully", result.username);
        Ok(result)
    }

    /// Finds a user by username.
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
                        metrics::db::query_failure("user_lookup_username_not_found");
                    }
                    _ => {
                        error!("Database error finding user {}: {}", username_str, e);
                        metrics::db::query_failure("user_lookup_username");
                    }
                }
                AuthServiceError::database("User not found")
            })
            .map(|user| {
                metrics::db::query_success("user_lookup_username");
                user
            })
    }

    /// Finds a user by email.
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
                        metrics::db::query_failure("user_lookup_email_not_found");
                    }
                    _ => {
                        error!("Database error finding user by email: {}", e);
                        metrics::db::query_failure("user_lookup_email");
                    }
                }
                AuthServiceError::database("User not found")
            })
            .map(|user| {
                metrics::db::query_success("user_lookup_email");
                user
            })
    }

    /// Activates the user's account.
    pub fn activate(&self, conn: &mut PgConnection) -> Result<(), AuthServiceError> {
        use crate::db::schema::users::dsl::*;
        
        conn.transaction(|conn| {
            diesel::update(users.filter(email.eq(&self.email)))
                .set(is_active.eq(true))
                .execute(conn)
        })
        .map_err(|e| {
            error!("Failed to activate account for {}: {}", self.email, e);
            metrics::db::query_failure("user_activate");
            AuthServiceError::database("Failed to activate account")
        })?;

        metrics::db::query_success("user_activate");
        info!("Account activated for {}", self.email);
        Ok(())
    }

    /// Updates the user record.
    pub fn update(&self, conn: &mut PgConnection) -> Result<(), AuthServiceError> {
        use crate::db::schema::users::dsl::*;
        
        conn.transaction(|conn| {
            diesel::update(users.filter(id.eq(self.id)))
                .set(self)
                .execute(conn)
        })
        .map_err(|e| {
            error!("Failed to update user {}: {}", self.username, e);
            metrics::db::query_failure("user_update");
            AuthServiceError::database("Failed to update user")
        })?;

        metrics::db::query_success("user_update");
        Ok(())
    }

    /// Sets a new password and updates the user.
    pub fn set_password_and_update(
        &mut self,
        conn: &mut PgConnection,
        new_password: &str,
    ) -> Result<(), AuthServiceError> {
        self.password_hash = Self::hash_password(new_password);
        
        conn.transaction(|conn| self.update(conn))
            .map_err(|e| {
                metrics::db::query_failure("user_password_update");
                e
            })?;

        metrics::db::query_success("user_password_update");
        info!("Password updated for user {}", self.username);
        Ok(())
    }

    /// Checks if the account is active.
    pub fn is_account_active(&self) -> bool {
        self.is_active
    }

    /// Returns safe user information for frontend.
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
        let user = User::new("alice", "alice@example.com", "Secret123!");
        
        assert_eq!(user.username, "alice");
        assert_eq!(user.is_active, false);
        assert!(user.verify_password("Secret123!").unwrap());
        assert!(!user.verify_password("wrong").unwrap());
    }

    #[test]
    fn test_password_hash_uniqueness() {
        let hash1 = User::hash_password("password");
        let hash2 = User::hash_password("password");
        
        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
        
        // Both should verify correctly
        let ph1 = PasswordHash::new(&hash1).unwrap();
        let ph2 = PasswordHash::new(&hash2).unwrap();
        
        assert!(Argon2::default()
            .verify_password(b"password", &ph1)
            .is_ok());
        assert!(Argon2::default()
            .verify_password(b"password", &ph2)
            .is_ok());
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
            password_hash: "hash".to_string(),
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
    fn test_is_account_active() {
        let mut user = User::new("test", "test@example.com", "Pass123!");
        assert!(!user.is_account_active());
        
        user.is_active = true;
        assert!(user.is_account_active());
    }

    #[test]
    fn test_password_verification_with_invalid_hash() {
        let mut user = User::new("test", "test@example.com", "Pass123!");
        user.password_hash = "invalid_hash".to_string();
        
        // Should return an error for invalid hash format
        assert!(user.verify_password("Pass123!").is_err());
    }
}