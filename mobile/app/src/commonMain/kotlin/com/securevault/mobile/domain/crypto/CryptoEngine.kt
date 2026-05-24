package com.securevault.mobile.domain.crypto

expect class CryptoEngine {
    fun generateSalt(): String
    fun generateAuthHash(password: String, salt: String): String
    fun generateVaultKey(): String
    fun deriveKek(password: String, encryptionSalt: String): ByteArray
    fun wrapVaultKey(vaultKey: String, kek: ByteArray): String
    fun unwrapVaultKey(wrappedVaultKey: String, kek: ByteArray): String
}
