use core::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidInput(&'static str),
    Base64,
    Kdf,
    Encrypt,
    DecryptionFailed,
    Rng,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "invalid key length"),
            CryptoError::InvalidInput(m) => write!(f, "invalid input: {m}"),
            CryptoError::Base64 => write!(f, "base64 decode failed"),
            CryptoError::Kdf => write!(f, "key derivation failed"),
            CryptoError::Encrypt => write!(f, "encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed"),
            CryptoError::Rng => write!(f, "RNG failure"),
        }
    }
}

impl std::error::Error for CryptoError {}
