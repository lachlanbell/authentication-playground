use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Internal error within libsodium.
    SodiumError,

    /// Invalid key length.
    InvalidKeyLength,

    /// The message could not be authenticated.
    ForgedMessage,

    /// The ciphertext is too short.
    CiphertextTooShort,

    /// Internal error within Argon2.
    Argon2Error(argon2::Error),

    /// Password hash error.
    PasswordHashError(argon2::password_hash::Error),

    /// Tokio task join error.
    JoinError(String),

    /// The token bytes could not be parsed.
    InvalidSessionToken,

    /// The session token has expired.
    ExpiredSessionToken,

    /// SQLx database error.
    DatabaseError(String),

    /// The username already exists.
    UsernameAlreadyExists,

    /// The user does not exist.
    NoSuchUser,

    /// Invalid credentials.
    InvalidCredentials,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::SodiumError => "internal error within libsodium",
            Error::InvalidKeyLength => "invalid key length",
            Error::ForgedMessage => "the message could not be authenticated",
            Error::CiphertextTooShort => "the ciphertext is too short",
            Error::Argon2Error(inner) => return write!(f, "internal error within argon2: {inner}"),
            Error::PasswordHashError(inner) => return write!(f, "password hash error: {inner}"),
            Error::JoinError(inner) => return write!(f, "tokio task failed to join: {inner}"),
            Error::InvalidSessionToken => "failed to parse session token",
            Error::ExpiredSessionToken => "the session token has expired",
            Error::DatabaseError(inner) => return write!(f, "database error: {inner}"),
            Error::UsernameAlreadyExists => "the username already exists",
            Error::NoSuchUser => "the user does not exist",
            Error::InvalidCredentials => "invalid credentials",
        })
    }
}

impl From<argon2::Error> for Error {
    fn from(value: argon2::Error) -> Self {
        Error::Argon2Error(value)
    }
}

impl From<argon2::password_hash::Error> for Error {
    fn from(value: argon2::password_hash::Error) -> Self {
        Error::PasswordHashError(value)
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(value: tokio::task::JoinError) -> Self {
        Error::JoinError(value.to_string())
    }
}

impl From<sqlx::Error> for Error {
    fn from(value: sqlx::Error) -> Self {
        Error::DatabaseError(value.to_string())
    }
}
