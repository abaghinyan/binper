use core::{result, fmt};
#[cfg(feature = "std")]
use std::{error, io};
use scroll;

#[derive(Debug)]
pub enum Error {
    BadSignature(u64),
    Scroll(scroll::Error),
    #[cfg(feature = "std")]
    IO(io::Error),
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::IO(ref io) => Some(io),
            Error::Scroll(ref scroll) => Some(scroll),
            Error::BadSignature(_) => None
        }
    }
}

#[cfg(feature = "std")]
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<scroll::Error> for Error {
    fn from(err: scroll::Error) -> Error {
        Error::Scroll(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "std")]
            Error::IO(ref err) => write!(fmt, "{}", err),
            Error::Scroll(ref err) => write!(fmt, "{}", err),
            Error::BadSignature(signature) => write!(fmt, "Invalid signature: 0x{:x}", signature),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;
