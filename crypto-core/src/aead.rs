use crate::error::CryptoError;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

pub(crate) const NONCE_LEN: usize = 12;

pub(crate) fn encrypt(key: &[u8], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)
}

pub(crate) fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::InvalidInput("nonce must be 12 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}
