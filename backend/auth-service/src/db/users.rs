use crate::db::schema::users;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use diesel::prelude::*;
use diesel::{AsChangeset, Insertable, Queryable};
use serde::{Deserialize, Serialize};
use log::{info, error};

/// Represents a user in the database.
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Option<i32>, // ID is optional for new users
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: Option<bool>, // Nowe pole wskazujące czy konto jest aktywne
}

/// Data structure for receiving registration data.
#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterData {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Data structure for receiving login data.
#[derive(Serialize, Deserialize,Debug)]
pub struct LoginData {
    pub username: String,
    pub password: String,
}

impl User {
    /// Creates a new user with a hashed password.
    pub fn new(username: &str, email: &str, password: &str) -> Self {
        let password_hash = User::hash_password(password);
        info!("Creating new user with username: {} and email: {}", username, email);
        User {
            id: None,
            username: username.to_string(),
            email: email.to_string(),
            password_hash,
            is_active: Some(false), // Nowe konto jest nieaktywne
        }
    }

    /// Hashes a password using Argon2.
    fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Password hashing failed")
            .to_string();
        info!("Password hashed successfully");
        hash
    }

    /// Verifies a password against the stored hash.
    pub fn verify_password(&self, password: &str) -> Result<bool, argon2::password_hash::Error> {
        let parsed_hash = PasswordHash::new(&self.password_hash)?;
        let is_verified = Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok();
        if is_verified {
            info!("Password verification successful for user: {}", self.username);
        } else {
            error!("Password verification failed for user: {}", self.username);
        }
        Ok(is_verified)
    }

    /// Saves the user in the database.
    pub fn save(&self, conn: &mut SqliteConnection) -> Result<usize, diesel::result::Error> {
        conn.transaction(|conn| {
            match diesel::insert_into(users::table)
                .values(self)
                .execute(conn) {
                    Ok(rows) => {
                        info!("Successfully inserted {} row(s) for user: {}", rows, self.username);
                        Ok(rows)
                    },
                    Err(e) => {
                        error!("Failed to insert user: {}. Error: {:?}", self.username, e);
                        Err(e)
                    }
                }
        })
    }

    /// Finds a user by username in the database.
    pub fn find_by_username(conn: &mut SqliteConnection, username_str: &str) -> QueryResult<Self> {
        use crate::db::schema::users::dsl::*;
        match users.filter(username.eq(username_str)).first(conn) {
            Ok(user) => {
                info!("User found with username: {}", username_str);
                Ok(user)
            },
            Err(e) => {
                error!("Failed to find user with username: {}. Error: {:?}", username_str, e);
                Err(e)
            }
        }
    }

    /// Finds a user by email in the database.
    pub fn find_by_email(conn: &mut SqliteConnection, email_str: &str) -> QueryResult<Self> {
        use crate::db::schema::users::dsl::*;
        match users.filter(email.eq(email_str)).first(conn) {
            Ok(user) => {
                info!("User found with email: {}", email_str);
                Ok(user)
            },
            Err(e) => {
                error!("Failed to find user with email: {}. Error: {:?}", email_str, e);
                Err(e)
            }
        }
    }

    /// Activates the user's account by setting `is_active` to true.
    pub fn activate(&self, conn: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
        use crate::db::schema::users::dsl::*;
        diesel::update(users.filter(email.eq(&self.email)))
            .set(is_active.eq(true))
            .execute(conn)?;
        info!("User {} activated successfully", self.email);
        Ok(())
    }

    pub fn update(&self, conn: &mut SqliteConnection) -> QueryResult<()> {
        use crate::db::schema::users::dsl::*;
        
        if let Some(user_id) = self.id {
            diesel::update(users.filter(id.eq(user_id)))
                .set(self)
                .execute(conn)
                .map(|_| ())
        } else {
            Err(diesel::result::Error::NotFound)
        }
    }

}