package com.securevault.mobile.domain.crypto

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual class CryptoEngine {

    private val secureRandom = SecureRandom()
    private val argon2Kt = Argon2Kt()
    private val argon2Iterations = 4
    private val argon2MemoryKb = 65536
    private val argon2Parallelism = 4
    private val keyLength = 32

    actual fun generateSalt(): String {
        val salt = ByteArray(16)
        secureRandom.nextBytes(salt)
        return Base64.getEncoder().encodeToString(salt)
    }

    actual fun generateAuthHash(password: String, salt: String): String {
        val saltBytes = Base64.getDecoder().decode(salt)
        val hash = argon2Kt.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password.toByteArray(Charsets.UTF_8),
            salt = saltBytes,
            tCostInIterations = argon2Iterations,
            mCostInKibibyte = argon2MemoryKb,
            parallelism = argon2Parallelism,
            hashLengthInBytes = keyLength
        )
        return Base64.getEncoder().encodeToString(hash.rawHashAsByteArray())
    }

    actual fun generateVaultKey(): String {
        val key = ByteArray(keyLength)
        secureRandom.nextBytes(key)
        return Base64.getEncoder().encodeToString(key)
    }

    actual fun deriveKek(password: String, encryptionSalt: String): ByteArray {
        val saltBytes = Base64.getDecoder().decode(encryptionSalt)
        val hash = argon2Kt.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password.toByteArray(Charsets.UTF_8),
            salt = saltBytes,
            tCostInIterations = argon2Iterations,
            mCostInKibibyte = argon2MemoryKb,
            parallelism = argon2Parallelism,
            hashLengthInBytes = keyLength
        )
        return hash.rawHashAsByteArray()
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
}
