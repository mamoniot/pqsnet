use core::fmt;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Error {
    /// The packet received was invalidly encoded.
    Invalid,
    /// The message contained in the received packet could not be authenticated.
    Inauthentic,
    AllocFailure,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ReplyError {
    /// The packet received was invalidly encoded.
    Invalid,
    /// The message contained in the received packet could not be authenticated.
    Inauthentic,
    InvalidPayload,
    IncorrectResumption,
    AllocFailure,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum AuthError {
    Invalid,
    Inauthentic,
    ExpiredKey,
    PostdatedKey,
    UnrecognizedVersion,
    AllocFailure,
}

impl From<Error> for ReplyError {
    fn from(value: Error) -> Self {
        match value {
            Error::Invalid => Self::Invalid,
            Error::Inauthentic => Self::Inauthentic,
            Error::AllocFailure => Self::AllocFailure,
        }
    }
}

impl From<AuthError> for Error {
    fn from(value: AuthError) -> Self {
        match value {
            AuthError::Invalid => Error::Invalid,
            AuthError::Inauthentic => Error::Inauthentic,
            AuthError::ExpiredKey => Error::Invalid,
            AuthError::PostdatedKey => Error::Invalid,
            AuthError::UnrecognizedVersion => Error::Invalid,
            AuthError::AllocFailure => Error::AllocFailure,
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Invalid => write!(f, "invalid"),
            AuthError::Inauthentic => write!(f, "inauthentic"),
            AuthError::ExpiredKey => write!(f, "expired key"),
            AuthError::PostdatedKey => write!(f, "postdated key"),
            AuthError::UnrecognizedVersion => write!(f, "unrecognized key version"),
            AuthError::AllocFailure => write!(f, "memory allocation failed"),
        }
    }
}

impl core::error::Error for AuthError {}
