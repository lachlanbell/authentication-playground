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
    Argon2Error(argon2::password_hash::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::SodiumError => "internal error within libsodium",
            Error::ForgedMessage => "the message could not be authenticated",
            Error::CiphertextTooShort => "the ciphertext is too short",
            Error::Argon2Error(inner) => return write!(f, "internal error within argon2: {inner}"),
        })
    }
}

impl From<argon2::password_hash::Error> for Error {
    fn from(value: argon2::password_hash::Error) -> Self {
        Error::Argon2Error(value)
    }
}
