pub enum Error {
    /// The packet received was invalidly encoded.
    Invalid,
    /// The message contained in the received packet could not be authenticated.
    Inauthentic,
}
