package com.securevault.mobile.domain.crypto

actual class CryptoEngine {
    actual fun generateSalt(): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun generateAuthHash(password: String, salt: String): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun generateVaultKey(): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun deriveKek(password: String, encryptionSalt: String): ByteArray = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun wrapVaultKey(vaultKey: String, kek: ByteArray): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun unwrapVaultKey(wrappedVaultKey: String, kek: ByteArray): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun sha1Hex(data: String): String = throw NotImplementedError("iOS: use platform SHA-1 library")
}
