use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Internal error within libsodium.
    SodiumError,

    /// The message could not be authenticated.
    ForgedMessage,

    /// The ciphertext is too short.
    CiphertextTooShort,

    /// Internal error within Argon2.
    Argon2Error(argon2::Error),

    /// Password hash error.
    PasswordHashError(argon2::password_hash::Error),

    /// Tokio task join error.
    JoinError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::SodiumError => "internal error within libsodium",
            Error::ForgedMessage => "the message could not be authenticated",
            Error::CiphertextTooShort => "the ciphertext is too short",
            Error::Argon2Error(inner) => return write!(f, "internal error within argon2: {inner}"),
            Error::PasswordHashError(inner) => return write!(f, "password hash error: {inner}"),
            Error::JoinError => "tokio task failed to join",
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
    fn from(_value: tokio::task::JoinError) -> Self {
        Error::JoinError
    }
}
