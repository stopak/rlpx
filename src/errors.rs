use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum Errors {
    SocketClosedByRemote,
    PublicKeyError,
    NotHandled,
    #[cfg(test)]
    EncryptionDecryptionFailed,
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for Errors {}

#[derive(Debug)]
pub enum ECIESError {
    AuthencityVerificationFailed,
    InvalidFrameHeaderMac,
    InvalidFrameBodyMac,
    InvalidAckData,
    InvalidAckRlpData,
}

impl fmt::Display for ECIESError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for ECIESError {}
