// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Int4,  // PostgreSQL uses Int4 instead of Integer
        username -> Varchar,  // PostgreSQL uses Varchar instead of Text
        email -> Varchar,
        password_hash -> Varchar,
        is_active -> Bool,  // PostgreSQL uses Bool instead of Nullable<Bool>
    }
}
