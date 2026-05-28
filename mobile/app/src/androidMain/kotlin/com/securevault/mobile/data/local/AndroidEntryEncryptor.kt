package com.securevault.mobile.data.local

import android.os.Handler
import android.os.Looper
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

class AndroidEntryEncryptor : EntryEncryptor, VaultKeyManager {
    private val tag = "AndroidEntryEncryptor"
    private val algorithm = "AES/GCM/NoPadding"
    private val gcmIvLength = 12
    private val gcmTagLength = 128
    private val keyLength = 32

    private var cachedVaultKey: ByteArray? = null
    private val autoLockHandler = Handler(Looper.getMainLooper())
    private val autoLockDelayMs = 300000L
    private val autoLockRunnable = Runnable { clearCachedVaultKey() }

    private fun scheduleAutoLock() {
        autoLockHandler.removeCallbacks(autoLockRunnable)
        autoLockHandler.postDelayed(autoLockRunnable, autoLockDelayMs)
    }

    private fun touchAutoLock() {
        autoLockHandler.removeCallbacks(autoLockRunnable)
        autoLockHandler.postDelayed(autoLockRunnable, autoLockDelayMs)
    }

    private val argon2Iterations: Int get() = SessionManager.getKdfIterations()
    private val argon2MemoryKb: Int get() = SessionManager.getKdfMemory()
    private val argon2Parallelism: Int get() = SessionManager.getKdfParallelism()

    private fun deriveKek(password: String, saltBytes: ByteArray): ByteArray {
        val argon2Kt = Argon2Kt()
        val passwordBytes = password.toByteArray(Charsets.UTF_8)

        val result = argon2Kt.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = passwordBytes,
            salt = saltBytes,
            tCostInIterations = argon2Iterations,
            mCostInKibibyte = argon2MemoryKb,
            parallelism = argon2Parallelism,
            hashLengthInBytes = keyLength
        )

        passwordBytes.fill(0)

        return result.rawHashAsByteArray()
    }

    override fun unlockVault(password: String, encryptionSalt: String, wrappedVaultKey: String) {
        if (wrappedVaultKey.isEmpty()) throw IllegalStateException("Wrapped vault key not available")

        val saltBytes = Base64.decode(encryptionSalt, Base64.NO_WRAP)
        val kekBytes = deriveKek(password, saltBytes)
        saltBytes.fill(0)

        val combined = Base64.decode(wrappedVaultKey, Base64.NO_WRAP)

        val iv = combined.copyOfRange(0, gcmIvLength)
        val encrypted = combined.copyOfRange(gcmIvLength, combined.size)

        val secretKey = SecretKeySpec(kekBytes, "AES")
        val cipher = Cipher.getInstance(algorithm)
        val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val decrypted = cipher.doFinal(encrypted)
        cachedVaultKey = decrypted

        kekBytes.fill(0)

        scheduleAutoLock()
    }

    override fun wrapVaultKey(vaultKey: String, password: String, encryptionSalt: String): String {
        val saltBytes = Base64.decode(encryptionSalt, Base64.NO_WRAP)
        val kekBytes = deriveKek(password, saltBytes)
        saltBytes.fill(0)

        val vaultKeyBytes = Base64.decode(vaultKey, Base64.NO_WRAP)

        val iv = ByteArray(gcmIvLength)
        java.security.SecureRandom().nextBytes(iv)

        val secretKey = SecretKeySpec(kekBytes, "AES")
        val cipher = Cipher.getInstance(algorithm)
        val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        val encrypted = cipher.doFinal(vaultKeyBytes)
        vaultKeyBytes.fill(0)

        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)

        kekBytes.fill(0)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    override fun generateVaultKey(): String {
        val keyBytes = ByteArray(keyLength)
        java.security.SecureRandom().nextBytes(keyBytes)

        val previous = cachedVaultKey
        if (previous != null) previous.fill(0)

        cachedVaultKey = keyBytes.copyOf()
        val vaultKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP)
        keyBytes.fill(0)

        scheduleAutoLock()
        return vaultKey
    }

    override fun generateEncryptionSalt(): String {
        val saltBytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(saltBytes)
        return Base64.encodeToString(saltBytes, Base64.NO_WRAP)
    }

    override fun getCachedVaultKey(): String? {
        touchAutoLock()
        return cachedVaultKey?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
    }

    override fun setCachedVaultKey(key: String) {
        val previous = cachedVaultKey
        if (previous != null) previous.fill(0)

        cachedVaultKey = Base64.decode(key, Base64.NO_WRAP)
        scheduleAutoLock()
    }

    override fun clearCachedVaultKey() {
        val previous = cachedVaultKey
        if (previous != null) {
            previous.fill(0)
            cachedVaultKey = null
        }
        autoLockHandler.removeCallbacks(autoLockRunnable)
    }

    private fun getEncryptionKey(): SecretKeySpec {
        val vaultKey = cachedVaultKey
            ?: throw IllegalStateException("Vault key not available. Please login first.")
        touchAutoLock()
        return SecretKeySpec(vaultKey, "AES")
    }

    override fun encrypt(entry: VaultEntry): VaultEntryRequest {
        val key = getEncryptionKey()
        val cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key)

        val iv = cipher.iv
        val plaintext = Json.encodeToString(VaultEntry.serializer(), entry)
        val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cipher.doFinal(plaintextBytes)
        plaintextBytes.fill(0)

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
        decryptedBytes.fill(0)

        return Json.decodeFromString(VaultEntry.serializer(), plaintext).copy(id = response.id.hashCode().toLong())
    }

    override fun encryptField(plaintext: String): String {
        if (plaintext.isEmpty()) return ""
        val key = getEncryptionKey()
        val cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
        val ciphertext = cipher.doFinal(plaintextBytes)
        plaintextBytes.fill(0)
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
        val result = String(decrypted, Charsets.UTF_8)
        decrypted.fill(0)
        return result
    }
}