package com.securevault.mobile.domain.crypto

expect class CryptoEngine {
    fun generateSalt(): String
    fun generateAuthHash(password: String, salt: String, iterations: Int = 4, memory: Int = 65536, parallelism: Int = 4): String
    fun generateVaultKey(): String
    fun deriveKek(password: String, encryptionSalt: String, iterations: Int = 4, memory: Int = 65536, parallelism: Int = 4): ByteArray
    fun wrapVaultKey(vaultKey: String, kek: ByteArray): String
    fun unwrapVaultKey(wrappedVaultKey: String, kek: ByteArray): String
    fun sha1Hex(data: String): String
    fun generateSecureDeviceId(): String
}
