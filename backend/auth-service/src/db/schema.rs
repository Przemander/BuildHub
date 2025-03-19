// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Nullable<Integer>,
        username -> Text,
        email -> Text,
        password_hash -> Text,
        is_active -> Nullable<Bool>,
    }
}
