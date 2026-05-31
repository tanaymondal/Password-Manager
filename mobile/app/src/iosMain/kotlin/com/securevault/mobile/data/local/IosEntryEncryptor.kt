package com.securevault.mobile.data.local

import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.data.model.VaultEntryResponse
import com.securevault.mobile.data.repository.EntryEncryptor
import com.securevault.mobile.data.repository.VaultKeyManager
import com.securevault.mobile.domain.model.VaultEntry
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.get
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import platform.Foundation.NSData
import platform.Foundation.base64EncodedStringWithOptions
import platform.Foundation.create
import platform.Security.SecRandomCopyBytes

@OptIn(ExperimentalForeignApi::class)
class IosEntryEncryptor : EntryEncryptor, VaultKeyManager {
    private val entryVersionPrefix = "v1:"
    private var cachedVaultKey: ByteArray? = null

    override fun unlockVault(password: String, encryptionSalt: String, wrappedVaultKey: String) {
        if (wrappedVaultKey.isEmpty()) throw IllegalStateException("Wrapped vault key not available")
        val engine = com.securevault.mobile.domain.crypto.CryptoEngine()
        val kek = engine.deriveKek(password, encryptionSalt)
        val vaultKeyB64 = engine.unwrapVaultKey(wrappedVaultKey, kek)
        val data = NSData.create(base64EncodedString = vaultKeyB64, options = 0u) ?: return
        cachedVaultKey = ByteArray(data.length.toInt()).apply {
            val ptr = data.bytes!!.reinterpret<ByteVar>()
            var idx = 0; while (idx < size) { this.set(idx, ptr.get(idx)); idx++ }
        }
    }

    override fun wrapVaultKey(vaultKey: String, password: String, encryptionSalt: String): String {
        val engine = com.securevault.mobile.domain.crypto.CryptoEngine()
        val kek = engine.deriveKek(password, encryptionSalt)
        return engine.wrapVaultKey(vaultKey, kek)
    }

    override fun generateVaultKey(): String {
        val bytes = ByteArray(32)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 32uL, pinned.addressOf(0)) }
        cachedVaultKey = bytes.copyOf()
        return bytes.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = 32uL).base64EncodedStringWithOptions(0u)
        }
    }

    override fun generateEncryptionSalt(): String {
        val bytes = ByteArray(16)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 16uL, pinned.addressOf(0)) }
        return bytes.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = 16uL).base64EncodedStringWithOptions(0u)
        }
    }

    override fun getCachedVaultKey(): String? {
        return cachedVaultKey?.let { bytes ->
            bytes.usePinned { pinned ->
                NSData.create(bytes = pinned.addressOf(0), length = bytes.size.toULong()).base64EncodedStringWithOptions(0u)
            }
        }
    }

    override fun setCachedVaultKey(key: String) {
        val data = NSData.create(base64EncodedString = key, options = 0u) ?: return
        cachedVaultKey = ByteArray(data.length.toInt()).apply {
            val ptr = data.bytes!!.reinterpret<ByteVar>()
            var idx = 0; while (idx < size) { this.set(idx, ptr.get(idx)); idx++ }
        }
    }

    override fun clearCachedVaultKey() {
        cachedVaultKey?.fill(0)
        cachedVaultKey = null
    }

    override fun encrypt(entry: VaultEntry): VaultEntryRequest {
        val vkB64 = vaultKeyB64()
        val plaintext = Json.encodeToString(VaultEntry.serializer(), entry)
        val result = SecureVaultCryptoCore.securevault_encrypt_entry(vkB64, plaintext)
            ?: error("Rust encrypt_entry returned null")
        val json = result.toKString()
        val parsed = Json.parseToJsonElement(json).jsonObject
        return VaultEntryRequest(
            id = if (entry.id > 0) entry.id.toString() else null,
            encryptedData = parsed["encryptedData"]!!.toString().removeSurrounding("\""),
            iv = parsed["iv"]!!.toString().removeSurrounding("\""),
        )
    }

    override fun decrypt(response: VaultEntryResponse): VaultEntry {
        val vkB64 = vaultKeyB64()
        val plaintext = SecureVaultCryptoCore.securevault_decrypt_entry(vkB64, response.encryptedData, response.iv)
            ?: error("Rust decrypt_entry returned null")
        return Json.decodeFromString(VaultEntry.serializer(), plaintext.toKString())
            .copy(id = response.id.hashCode().toLong().let { if (it < 0) -it else it }, serverId = response.id)
    }

    override fun encryptField(plaintext: String): String {
        if (plaintext.isEmpty()) return ""
        val vkB64 = vaultKeyB64()
        val result = SecureVaultCryptoCore.securevault_encrypt_field(vkB64, plaintext)
            ?: error("Rust encrypt_field returned null")
        return result.toKString()
    }

    override fun decryptField(ciphertext: String): String {
        if (ciphertext.isEmpty()) return ""
        val vkB64 = vaultKeyB64()
        val result = SecureVaultCryptoCore.securevault_decrypt_field(vkB64, ciphertext)
            ?: error("Rust decrypt_field returned null")
        return result.toKString()
    }

    private fun vaultKeyB64(): String {
        val vk = cachedVaultKey ?: throw IllegalStateException("Vault key not available")
        return vk.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = vk.size.toULong()).base64EncodedStringWithOptions(0u)
        }
    }
}
