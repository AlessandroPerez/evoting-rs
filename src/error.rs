use core::fmt;
use dlog_sigma_primitives::error::{DecryptionError, Error as CryptoError};
//TODO: Model the errors in a better way but we can do it at the end, now this is good enough

// FIX:
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    InvalidSize(String),
    IdOutOfRange(usize),
    IdMissmatch(usize),
    DvKeysNotSet(usize),
    FailedVerification(CryptoError),
    FailedDecryption(DecryptionError),
    FailedCredentialControl(usize),
    FailedVerifiableDecryption(usize),
    CiphertextMismatch(String),
    DlogMismatch(String),
    Mismatch(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize(message) => write!(formatter, "Input has inconsistent size: {message}"),
            Self::IdOutOfRange(id) => write!(formatter, "The ID:{id} given in input is outside the range of RegistrationTeller"),
            Self::IdMissmatch(id) => write!(formatter, "The ID:{id} included in the Credential is different from the position inside the list!"),
            Self::DvKeysNotSet(id) => write!(formatter, "The Designated Verifier public key of ID:{id} is not set!"),
            Self::FailedVerification(err) => write!(formatter, "Verification Failed: {err}"),
            Self::FailedDecryption(err) => write!(formatter, "Decryption Failed"),
            Self::FailedCredentialControl(index) => write!(formatter, "The ID:{index} failed the credential control check"),
            Self::FailedVerifiableDecryption(index) => write!(formatter, "The ID:{index} failed the veryfiable decryption check"),
            Self::CiphertextMismatch(s) => write!(formatter, "Ciphertext mismatch: {s}"),
            Self::DlogMismatch(s) => write!(formatter, "Dlog mismatch: {s}"),
            Self::Mismatch(s) => write!(formatter, "Mismatch: {s}"),
        }
    }
}

impl From<dlog_sigma_primitives::error::Error> for Error {
    fn from(err: dlog_sigma_primitives::error::Error) -> Self {
        Error::FailedVerification(err)
    }
}

impl From<dlog_sigma_primitives::error::DecryptionError> for Error {
    fn from(err: dlog_sigma_primitives::error::DecryptionError) -> Self {
        Error::FailedDecryption(err)
    }
}
