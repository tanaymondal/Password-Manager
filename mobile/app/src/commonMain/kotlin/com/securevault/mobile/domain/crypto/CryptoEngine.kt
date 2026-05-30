package com.securevault.mobile.domain.crypto

expect class CryptoEngine {
    fun generateSalt(): String
    fun generateAuthHash(password: String, salt: String, iterations: Int = 3, memory: Int = 98304, parallelism: Int = 4): String

    fun deriveKek(password: String, encryptionSalt: String, iterations: Int = 3, memory: Int = 98304, parallelism: Int = 4): ByteArray
    fun wrapVaultKey(vaultKey: String, kek: ByteArray): String
    fun unwrapVaultKey(wrappedVaultKey: String, kek: ByteArray): String
    fun sha1Hex(data: String): String
    fun generateSecureDeviceId(): String
}
