package com.securevault.mobile.data.local

import android.util.Base64
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.data.model.VaultEntryResponse
import com.securevault.mobile.data.repository.EntryEncryptor
import com.securevault.mobile.data.repository.VaultKeyManager
import com.securevault.mobile.domain.model.VaultEntry
import kotlinx.serialization.json.Json
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class AndroidEntryEncryptor : EntryEncryptor, VaultKeyManager {
    private val tag = "AndroidEntryEncryptor"
    private val algorithm = "AES/GCM/NoPadding"
    private val gcmIvLength = 12
    private val gcmTagLength = 128
    private val keyLength = 32

    private val argon2Iterations = 4
    private val argon2MemoryKb = 65536
    private val argon2Parallelism = 4

    private var cachedVaultKey: String? = null

    private fun deriveKek(password: String, saltBytes: ByteArray): ByteArray {
        val argon2Kt = Argon2Kt()

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

    override fun unlockVault(password: String, encryptionSalt: String, wrappedVaultKey: String) {
        if (wrappedVaultKey.isEmpty()) throw IllegalStateException("Wrapped vault key not available")

        val saltBytes = Base64.decode(encryptionSalt, Base64.NO_WRAP)
        val kekBytes = deriveKek(password, saltBytes)
        val combined = Base64.decode(wrappedVaultKey, Base64.NO_WRAP)

        val iv = combined.copyOfRange(0, gcmIvLength)
        val encrypted = combined.copyOfRange(gcmIvLength, combined.size)

        val secretKey = SecretKeySpec(kekBytes, "AES")
        val cipher = Cipher.getInstance(algorithm)
        val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val decrypted = cipher.doFinal(encrypted)
        cachedVaultKey = Base64.encodeToString(decrypted, Base64.NO_WRAP)
    }

    override fun wrapVaultKey(vaultKey: String, password: String, encryptionSalt: String): String {
        val saltBytes = Base64.decode(encryptionSalt, Base64.NO_WRAP)
        val kekBytes = deriveKek(password, saltBytes)
        val vaultKeyBytes = Base64.decode(vaultKey, Base64.NO_WRAP)

        val iv = ByteArray(gcmIvLength)
        java.security.SecureRandom().nextBytes(iv)

        val secretKey = SecretKeySpec(kekBytes, "AES")
        val cipher = Cipher.getInstance(algorithm)
        val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        val encrypted = cipher.doFinal(vaultKeyBytes)

        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    override fun generateVaultKey(): String {
        val keyBytes = ByteArray(keyLength)
        java.security.SecureRandom().nextBytes(keyBytes)
        val vaultKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP)
        cachedVaultKey = vaultKey
        return vaultKey
    }

    override fun generateEncryptionSalt(): String {
        val saltBytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(saltBytes)
        return Base64.encodeToString(saltBytes, Base64.NO_WRAP)
    }

    override fun getCachedVaultKey(): String? = cachedVaultKey

    override fun setCachedVaultKey(key: String) {
        cachedVaultKey = key
    }

    override fun clearCachedVaultKey() {
        cachedVaultKey = null
    }

    private fun getEncryptionKey(): SecretKeySpec {
        val vaultKey = cachedVaultKey
            ?: throw IllegalStateException("Vault key not available. Please login first.")
        val keyBytes = Base64.decode(vaultKey, Base64.NO_WRAP)
        return SecretKeySpec(keyBytes, "AES")
    }

    override fun encrypt(entry: VaultEntry): VaultEntryRequest {
        val key = getEncryptionKey()
        val cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key)

        val iv = cipher.iv
        val plaintext = Json.encodeToString(VaultEntry.serializer(), entry)
        val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cipher.doFinal(plaintextBytes)

        val encryptedData = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        val ivString = Base64.encodeToString(iv, Base64.NO_WRAP)

        return VaultEntryRequest(
            id = if (entry.id > 0) entry.id.toString() else null,
            encryptedData = encryptedData,
            iv = ivString
        )
    }

    override fun decrypt(response: VaultEntryResponse): VaultEntry {
        val key = getEncryptionKey()
        val iv = Base64.decode(response.iv, Base64.NO_WRAP)
        val encryptedBytes = Base64.decode(response.encryptedData, Base64.NO_WRAP)

        val cipher = Cipher.getInstance(algorithm)
        val spec = GCMParameterSpec(gcmTagLength, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)

        val decryptedBytes = cipher.doFinal(encryptedBytes)
        val plaintext = String(decryptedBytes, Charsets.UTF_8)

        return Json.decodeFromString(VaultEntry.serializer(), plaintext).copy(id = response.id.hashCode().toLong())
    }

    override fun encryptField(plaintext: String): String {
        if (plaintext.isEmpty()) return ""
        val key = getEncryptionKey()
        val cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    override fun decryptField(ciphertext: String): String {
        if (ciphertext.isEmpty()) return ""
        val key = getEncryptionKey()
        val combined = Base64.decode(ciphertext, Base64.NO_WRAP)
        val iv = combined.copyOfRange(0, gcmIvLength)
        val encrypted = combined.copyOfRange(gcmIvLength, combined.size)
        val cipher = Cipher.getInstance(algorithm)
        val spec = GCMParameterSpec(gcmTagLength, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val decrypted = cipher.doFinal(encrypted)
        return String(decrypted, Charsets.UTF_8)
    }
}