package com.securevault.mobile.domain.crypto

import platform.Security.SecRandomCopyBytes
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned

actual class CryptoEngine {
    actual fun generateSalt(): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun generateAuthHash(password: String, salt: String): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun generateVaultKey(): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun deriveKek(password: String, encryptionSalt: String): ByteArray = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun wrapVaultKey(vaultKey: String, kek: ByteArray): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun unwrapVaultKey(wrappedVaultKey: String, kek: ByteArray): String = throw NotImplementedError("iOS: use platform Argon2 library")
    actual fun sha1Hex(data: String): String = throw NotImplementedError("iOS: use platform SHA-1 library")

    @OptIn(ExperimentalForeignApi::class)
    actual fun generateSecureDeviceId(): String {
        val bytes = ByteArray(16)
        bytes.usePinned { pinned ->
            SecRandomCopyBytes(null, 16, pinned.addressOf(0))
        }
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
