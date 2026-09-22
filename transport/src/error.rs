pub enum Error {
    /// The packet received was invalidly encoded.
    Invalid,
    /// The message contained in the received packet could not be authenticated.
    Inauthentic,
}

pub enum InitError {
    /// The packet received was invalidly encoded.
    Invalid,
    /// The message contained in the received packet could not be authenticated.
    Inauthentic,
    /// A resumption key is required to open this socket.
    ResumptionKeyRequired,
}

pub enum ReplyError {
    /// The packet received was invalidly encoded.
    Invalid,
    /// The message contained in the received packet could not be authenticated.
    Inauthentic,
    InvalidPayload,
}

impl From<Error> for ReplyError {
    fn from(value: Error) -> Self {
        match value {
            Error::Invalid => Self::Invalid,
            Error::Inauthentic => Self::Inauthentic,
        }
    }
}

impl From<Error> for InitError {
    fn from(value: Error) -> Self {
        match value {
            Error::Invalid => Self::Invalid,
            Error::Inauthentic => Self::Inauthentic,
        }
    }
}
