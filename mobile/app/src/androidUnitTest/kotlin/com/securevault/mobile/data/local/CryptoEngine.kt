package com.securevault.mobile.data.local

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.lambdapioneer.argon2kt.SoLoaderShim
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

class CryptoEngine(
    private val getPassword: () -> String,
    private val getEncryptionSalt: () -> String,
    private val soLoaderShim: SoLoaderShim? = null
) {
    private val algorithm = "AES/GCM/NoPadding"
    private val gcmIvLength = 12
    private val gcmTagLength = 128
    private val keyLength = 32

    private val argon2Iterations = 3
    private val argon2MemoryKb = 65536
    private val argon2Parallelism = 4

    private var cachedVaultKey: String? = null

    private fun deriveKek(): ByteArray = deriveKekForPassword(getPassword(), getEncryptionSalt())

    fun deriveKekForPassword(password: String, encryptionSalt: String): ByteArray {
        if (encryptionSalt.isEmpty()) throw IllegalStateException("Encryption salt not available")
        val saltBytes = Base64.getDecoder().decode(encryptionSalt)
        val loader = soLoaderShim ?: object : SoLoaderShim {
            override fun loadLibrary(name: String) = System.loadLibrary(name)
        }
        val argon2Kt = Argon2Kt(loader)
        val result = argon2Kt.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password.toByteArray(Charsets.UTF_8),
            salt = saltBytes,
            tCostInIterations = argon2Iterations,
            mCostInKibibyte = argon2MemoryKb,
            parallelism = argon2Parallelism,
            hashLengthInBytes = keyLength
        )
        return result.rawHashAsByteArray()
    }

    fun deriveKekBase64(password: String, encryptionSalt: String): String {
        val kekBytes = deriveKekForPassword(password, encryptionSalt)
        return Base64.getEncoder().encodeToString(kekBytes)
    }

    fun unwrapVaultKey(wrappedVaultKey: String): String {
        val kekBytes = deriveKek()
        return unwrapVaultKeyWithKek(wrappedVaultKey, kekBytes)
    }

    fun unwrapVaultKeyWithKek(wrappedVaultKey: String, kekBytes: ByteArray): String {
        val combined = Base64.getDecoder().decode(wrappedVaultKey)
        val iv = combined.copyOfRange(0, gcmIvLength)
        val encrypted = combined.copyOfRange(gcmIvLength, combined.size)
        val secretKey = SecretKeySpec(kekBytes, "AES")
        val cipher = Cipher.getInstance(algorithm)
        val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
        val decrypted = cipher.doFinal(encrypted)
        val vaultKey = Base64.getEncoder().encodeToString(decrypted)
        cachedVaultKey = vaultKey
        return vaultKey
    }

    fun wrapVaultKey(vaultKey: String): String {
        val kekBytes = deriveKek()
        return wrapVaultKeyWithKek(vaultKey, kekBytes)
    }

    fun wrapVaultKeyWithKek(vaultKey: String, kekBytes: ByteArray): String {
        val vaultKeyBytes = Base64.getDecoder().decode(vaultKey)
        val iv = ByteArray(gcmIvLength)
        SecureRandom().nextBytes(iv)
        val secretKey = SecretKeySpec(kekBytes, "AES")
        val cipher = Cipher.getInstance(algorithm)
        val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
        val encrypted = cipher.doFinal(vaultKeyBytes)
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)
        return Base64.getEncoder().encodeToString(combined)
    }

    fun generateVaultKey(): String {
        val keyBytes = ByteArray(keyLength)
        SecureRandom().nextBytes(keyBytes)
        val vaultKey = Base64.getEncoder().encodeToString(keyBytes)
        cachedVaultKey = vaultKey
        return vaultKey
    }

    fun generateEncryptionSalt(): String {
        val saltBytes = ByteArray(16)
        SecureRandom().nextBytes(saltBytes)
        return Base64.getEncoder().encodeToString(saltBytes)
    }

    fun getCachedVaultKey(): String? = cachedVaultKey

    fun setCachedVaultKey(key: String) {
        cachedVaultKey = key
    }

    fun clearCachedVaultKey() {
        cachedVaultKey = null
    }

    fun getCachedVaultKey(): String? = cachedVaultKey

    private fun getVaultKeyForEncryption(): String {
        return cachedVaultKey
            ?: throw IllegalStateException("Vault key not available. Please login first.")
    }

    fun encryptEntry(id: Long, title: String, username: String, password: String, url: String?, notes: String?, folder: String?): Pair<String, String> {
        val vaultKey = getVaultKeyForEncryption()
        val keyBytes = Base64.getDecoder().decode(vaultKey)
        val secretKey = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val plaintext = "$id|$title|$username|$password|${url ?: ""}|${notes ?: ""}|${folder ?: ""}"
        val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cipher.doFinal(plaintextBytes)
        return Pair(
            Base64.getEncoder().encodeToString(encryptedBytes),
            Base64.getEncoder().encodeToString(iv)
        )
    }

    fun decryptEntry(encryptedData: String, iv: String): Map<String, String?> {
        val vaultKey = getVaultKeyForEncryption()
        val keyBytes = Base64.getDecoder().decode(vaultKey)
        val secretKey = SecretKeySpec(keyBytes, "AES")
        val ivBytes = Base64.getDecoder().decode(iv)
        val encryptedBytes = Base64.getDecoder().decode(encryptedData)
        val cipher = Cipher.getInstance(algorithm)
        val spec = GCMParameterSpec(gcmTagLength, ivBytes)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        val plaintext = String(decryptedBytes, Charsets.UTF_8)
        val parts = plaintext.split("|")
        return mapOf(
            "id" to parts.getOrElse(0) { "0" },
            "title" to parts.getOrElse(1) { "" },
            "username" to parts.getOrElse(2) { "" },
            "password" to parts.getOrElse(3) { "" },
            "url" to parts.getOrElse(4) { "" }.ifEmpty { null },
            "notes" to parts.getOrElse(5) { "" }.ifEmpty { null },
            "folder" to parts.getOrElse(6) { "" }.ifEmpty { null }
        )
    }
}
