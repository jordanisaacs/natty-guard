use core::fmt;
use std::{
    borrow::Cow,
    error::Error,
    ffi::{CStr, NulError},
    fmt::write,
    str::FromStr,
};

use libc::c_char;

mod kernel;

pub use kernel::*;

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct InvalidKey;

impl std::error::Error for InvalidKey {}

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid key format")
    }
}

impl From<NulError> for InvalidKey {
    fn from(_: NulError) -> Self {
        InvalidKey {}
    }
}

#[derive(Eq, PartialEq, Clone)]
pub struct Key(pub [u8; 32]);

impl Key {
    pub fn to_base64(&self) -> String {
        base64::encode(self.0)
    }

    pub fn from_base64(key: &str) -> Result<Self, InvalidKey> {
        let mut key_bytes = [0u8; 32];
        let decoded_bytes = base64::decode(key).map_err(|_| InvalidKey)?;

        if decoded_bytes.len() != 32 {
            return Err(InvalidKey);
        }

        key_bytes.copy_from_slice(&decoded_bytes[..]);
        Ok(Self(key_bytes))
    }
}

pub struct Device {
    pub name: InterfaceName,
    pub public_key: Option<Key>,
}

/// A bad interface name
#[derive(Debug, PartialEq)]
pub enum InvalidInterfaceName {
    /// Name was longer then the interface name length limit of system
    TooLong,
    /// Name was an empty string
    Empty,
    /// Name contained a nul, '/', or whitespace character
    InvalidChars,
}

impl fmt::Display for InvalidInterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(
                f,
                "interface name is longer than system max of {} chars",
                libc::IFNAMSIZ,
            ),
            Self::Empty => f.write_str("an empty interface name was provided"),
            Self::InvalidChars => {
                f.write_str("interface name contained slash or space or nul characters")
            }
        }
    }
}

type RawInterfaceName = [c_char; libc::IFNAMSIZ];

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct InterfaceName(RawInterfaceName);

impl fmt::Debug for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str_lossy())
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str_lossy())
    }
}

impl FromStr for InterfaceName {
    type Err = InvalidInterfaceName;

    /// Attempt to parse a Rust string as a valid Linux interface name
    ///
    /// Extra validation logic ported from [iproute2](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/lib/utils.c#n827)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let len = s.len();
        if len == 0 {
            return Err(InvalidInterfaceName::Empty);
        }

        // Compensate for trailing NUL
        if len > (libc::IFNAMSIZ - 1) {
            return Err(InvalidInterfaceName::TooLong);
        }

        let mut buf = [c_char::default(); libc::IFNAMSIZ];
        for (out, b) in buf.iter_mut().zip(s.as_bytes().iter()) {
            if *b == 0 || *b == b'/' || b.is_ascii_whitespace() {
                return Err(InvalidInterfaceName::InvalidChars);
            }

            *out = *b as c_char;
        }

        Ok(Self(buf))
    }
}

impl InterfaceName {
    /// Returns a human-readable form of the device name
    ///
    /// Only use when the interface name was constructed from a Rust string
    pub fn as_str_lossy(&self) -> Cow<'_, str> {
        // SAFETY: The C strings come from rust so they are correctly NUL terminated
        unsafe { CStr::from_ptr(self.0.as_ptr()) }.to_string_lossy()
    }

    pub fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr()
    }
}

impl Error for InvalidInterfaceName {}

#[cfg(test)]
mod tests {
    use crate::Key;

    #[test]
    fn base64_key() {
        let key = Key([0u8; 32]);
        let b64 = key.to_base64();
        assert!(Key::from_base64(&b64).unwrap() == key);
    }
}
