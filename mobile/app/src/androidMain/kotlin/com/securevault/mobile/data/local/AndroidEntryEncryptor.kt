package com.securevault.mobile.data.local

import android.util.Base64
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.data.model.VaultEntryResponse
import com.securevault.mobile.data.repository.EntryEncryptor
import com.securevault.mobile.data.repository.SessionManager
import com.securevault.mobile.data.repository.VaultKeyManager
import com.securevault.mobile.domain.model.VaultEntry
import kotlinx.serialization.json.Json
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Log

class AndroidEntryEncryptor : EntryEncryptor, VaultKeyManager {
    private val tag = "AndroidEntryEncryptor"
    private val algorithm = "AES/GCM/NoPadding"
    private val gcmIvLength = 12
    private val gcmTagLength = 128
    private val keyLength = 32

    private val argon2Iterations = 3
    private val argon2MemoryKb = 65536
    private val argon2Parallelism = 4

    private var cachedVaultKey: String? = null

    private fun deriveKek(): ByteArray {
        val password = SessionManager.getMasterPassword()
        val encryptionSalt = SessionManager.getEncryptionSalt()
        Log.d(tag, "deriveKek: salt length=${encryptionSalt.length}, salt=${encryptionSalt}")
        if (encryptionSalt.isEmpty()) throw IllegalStateException("Encryption salt not available")

        val saltBytes = Base64.decode(encryptionSalt, Base64.NO_WRAP)
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

    override fun unwrapVaultKey(wrappedVaultKey: String): String {
        try {
            Log.d(tag, "unwrapVaultKey: START")
            if (wrappedVaultKey.isEmpty()) throw IllegalStateException("Wrapped vault key not available")

            val kekBytes = deriveKek()
            val combined = Base64.decode(wrappedVaultKey, Base64.NO_WRAP)

            val iv = combined.copyOfRange(0, gcmIvLength)
            val encrypted = combined.copyOfRange(gcmIvLength, combined.size)

            val secretKey = SecretKeySpec(kekBytes, "AES")
            val cipher = Cipher.getInstance(algorithm)
            val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

            val decrypted = cipher.doFinal(encrypted)
            val vaultKey = Base64.encodeToString(decrypted, Base64.NO_WRAP)
            cachedVaultKey = vaultKey

            Log.d(tag, "unwrapVaultKey: SUCCESS, cachedVaultKey set (length=${vaultKey.length})")
            return vaultKey
        } catch (e: Exception) {
            Log.e(tag, "Failed to unwrap vault key: ${e.message}")
            throw e
        }
    }

    override fun wrapVaultKey(vaultKey: String): String {
        try {
            val kekBytes = deriveKek()
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
        } catch (e: Exception) {
            Log.e(tag, "Failed to wrap vault key: ${e.message}")
            throw e
        }
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
        val salt = Base64.encodeToString(saltBytes, Base64.NO_WRAP)
        Log.d(tag, "generateEncryptionSalt: $salt")
        return salt
    }

    override fun getCachedVaultKey(): String? = cachedVaultKey

    override fun setCachedVaultKey(key: String) {
        cachedVaultKey = key
        Log.d(tag, "setCachedVaultKey: key length=${key.length}")
    }

    override fun clearCachedVaultKey() {
        Log.d(tag, "clearCachedVaultKey: CALLED")
        cachedVaultKey = null
    }

    private fun getEncryptionKey(): SecretKeySpec {
        Log.d(tag, "getEncryptionKey: cachedVaultKey=${cachedVaultKey != null}")
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

        Log.d(tag, "Encrypted entry: encryptedData length=${encryptedData.length}, iv length=${ivString.length}")
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

        return try {
            Json.decodeFromString(VaultEntry.serializer(), plaintext)
        } catch (e: Exception) {
            val parts = plaintext.split("|")
            VaultEntry(
                id = response.id.hashCode().toLong(),
                title = parts.getOrElse(0) { "" },
                username = parts.getOrElse(1) { "" },
                password = parts.getOrElse(2) { "" },
                url = parts.getOrElse(3) { "" }.ifEmpty { null },
                notes = parts.getOrElse(4) { "" }.ifEmpty { null },
                folder = parts.getOrElse(5) { "" }.ifEmpty { null }
            )
        }
    }
}