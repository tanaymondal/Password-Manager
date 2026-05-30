use crate::error::CryptoError;
use crate::params::KdfParams;
use argon2::{Algorithm, Argon2, Params, Version};

pub(crate) fn argon2id_raw(
    password: &[u8],
    salt: &[u8],
    p: &KdfParams,
) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(p.memory_kib, p.iterations, p.parallelism, Some(32))
        .map_err(|_| CryptoError::Kdf)?;
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    hasher
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}
