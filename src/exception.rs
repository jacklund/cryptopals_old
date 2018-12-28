use std::error;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum CryptoError {
    BadPadding,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoError::BadPadding => write!(f, "Bad PKCS7 padding"),
        }
    }
}

impl error::Error for CryptoError {
    fn description(&self) -> &str {
        match *self {
            CryptoError::BadPadding => "Bad PKCS7 padding",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            CryptoError::BadPadding => None,
        }
    }
}
