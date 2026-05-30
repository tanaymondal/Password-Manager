package com.securevault.mobile.domain.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual class CryptoEngine {

    private val secureRandom = SecureRandom()
    private val keyLength = 32

    actual fun generateSalt(): String {
        val salt = ByteArray(16)
        secureRandom.nextBytes(salt)
        return Base64.getEncoder().encodeToString(salt)
    }

    actual fun generateAuthHash(password: String, salt: String, iterations: Int, memory: Int, parallelism: Int): String {
        return RustCryptoCore.deriveAuthHash(password, salt, iterations, memory, parallelism)
    }

    actual fun generateVaultKey(): String {
        val key = ByteArray(keyLength)
        secureRandom.nextBytes(key)
        return Base64.getEncoder().encodeToString(key)
    }

    actual fun deriveKek(password: String, encryptionSalt: String, iterations: Int, memory: Int, parallelism: Int): ByteArray {
        return RustCryptoCore.deriveKek(password, encryptionSalt, iterations, memory, parallelism)
    }

    actual fun wrapVaultKey(vaultKey: String, kek: ByteArray): String {
        val vaultKeyBytes = Base64.getDecoder().decode(vaultKey)
        val iv = ByteArray(12)
        secureRandom.nextBytes(iv)

        val keySpec = SecretKeySpec(kek, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, iv))

        val encrypted = cipher.doFinal(vaultKeyBytes)
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

        return Base64.getEncoder().encodeToString(combined)
    }

    actual fun unwrapVaultKey(wrappedVaultKey: String, kek: ByteArray): String {
        val combined = Base64.getDecoder().decode(wrappedVaultKey)
        val iv = combined.copyOfRange(0, 12)
        val encrypted = combined.copyOfRange(12, combined.size)

        val keySpec = SecretKeySpec(kek, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(128, iv))

        val decrypted = cipher.doFinal(encrypted)
        return Base64.getEncoder().encodeToString(decrypted)
    }

    actual fun sha1Hex(data: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        val hash = digest.digest(data.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }.uppercase()
    }

    actual fun generateSecureDeviceId(): String {
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
