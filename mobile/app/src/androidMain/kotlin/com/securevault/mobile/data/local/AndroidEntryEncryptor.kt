package com.securevault.mobile.data.local

import android.util.Base64
import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.data.model.VaultEntryResponse
import com.securevault.mobile.data.repository.EntryEncryptor
import com.securevault.mobile.data.repository.SessionManager
import com.securevault.mobile.domain.model.VaultEntry
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import android.util.Log

class AndroidEntryEncryptor : EntryEncryptor {
    private val tag = "AndroidEntryEncryptor"
    private val algorithm = "AES/GCM/NoPadding"
    private val keyLength = 256
    private val iterationCount = 65536
    private val keyLengthBytes = 32
    private val ivLength = 12
    private val tagLength = 128

    private fun deriveKey(salt: ByteArray): SecretKeySpec {
        val password = SessionManager.getMasterPassword().toCharArray()
        val saltBytes = Base64.decode(salt, Base64.NO_WRAP)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password, saltBytes, iterationCount, keyLength)
        val secretKey = factory.generateSecret(spec)
        return SecretKeySpec(secretKey.encoded, "AES")
    }

    override fun encrypt(entry: VaultEntry): VaultEntryRequest {
        val salt = SessionManager.getEncryptionSalt()
        if (salt.isEmpty()) throw IllegalStateException("Encryption salt not available")
        val saltBytes = salt.toByteArray(Charsets.UTF_8)

        val key = deriveKey(saltBytes)
        val cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key)

        val iv = cipher.iv
        val plaintext = "${entry.title}|${entry.username}|${entry.password}|${entry.url ?: ""}|${entry.notes ?: ""}|${entry.folder ?: ""}"
        val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
        val encryptedBytes = cipher.doFinal(plaintextBytes)

        val encryptedData = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        val ivString = Base64.encodeToString(iv, Base64.NO_WRAP)

        Log.d(tag, "Encrypted entry: encryptedData length=${encryptedData.length}, iv length=${ivString.length}")
        return VaultEntryRequest(encryptedData, ivString)
    }

    override fun decrypt(response: VaultEntryResponse): VaultEntry {
        val salt = SessionManager.getEncryptionSalt()
        if (salt.isEmpty()) throw IllegalStateException("Encryption salt not available")
        val saltBytes = salt.toByteArray(Charsets.UTF_8)

        val key = deriveKey(saltBytes)
        val iv = Base64.decode(response.iv, Base64.NO_WRAP)
        val encryptedBytes = Base64.decode(response.encryptedData, Base64.NO_WRAP)

        val cipher = Cipher.getInstance(algorithm)
        val spec = GCMParameterSpec(tagLength, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)

        val decryptedBytes = cipher.doFinal(encryptedBytes)
        val plaintext = String(decryptedBytes, Charsets.UTF_8)
        val parts = plaintext.split("|")

        return VaultEntry(
            id = response.id.toLongOrNull() ?: 0L,
            title = parts.getOrElse(0) { "" },
            username = parts.getOrElse(1) { "" },
            password = parts.getOrElse(2) { "" },
            url = parts.getOrElse(3) { "" }.ifEmpty { null },
            notes = parts.getOrElse(4) { "" }.ifEmpty { null },
            folder = parts.getOrElse(5) { "" }.ifEmpty { null }
        )
    }
}
