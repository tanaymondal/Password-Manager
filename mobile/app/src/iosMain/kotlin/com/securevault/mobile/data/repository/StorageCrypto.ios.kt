package com.securevault.mobile.data.repository

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSJSONSerialization
import platform.Foundation.NSUserDomainMask
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.NSFileProtectionComplete
import platform.Foundation.NSFileProtectionKey
import platform.Foundation.base64EncodedStringWithOptions
import platform.Foundation.create
import platform.Foundation.writeToFile
import platform.Security.SecRandomCopyBytes

private const val KEY_FILE = ".sv_device_key"
private var cachedDeviceKey: String? = null

@OptIn(ExperimentalForeignApi::class)
private fun getOrCreateDeviceKey(): String {
    cachedDeviceKey?.let { return it }

    val path = getDeviceKeyPath()
    val data = NSData.create(contentsOfFile = path)
    if (data != null) {
        val obj = NSJSONSerialization.JSONObjectWithData(data, 0u, null) as? Map<*, *>
        val key = (obj as? Map<String, String>)?.get("key")
        if (key != null) {
            cachedDeviceKey = key
            return key
        }
    }

    // Generate new 32-byte key, base64 encode
    val keyBytes = ByteArray(32)
    keyBytes.usePinned { pinned ->
        SecRandomCopyBytes(null, 32uL, pinned.addressOf(0))
    }
    val keyB64: String = keyBytes.usePinned { pinned ->
        NSData.create(bytes = pinned.addressOf(0), length = 32uL).base64EncodedStringWithOptions(0u)
    }

    // Store to file with complete protection (unreadable when locked)
    val json = mapOf<String, String>("key" to keyB64)
    val outData = NSJSONSerialization.dataWithJSONObject(json, 0u, null) ?: error("Failed to serialize key")
    outData.writeToFile(path, atomically = true)
    NSFileManager.defaultManager.setAttributes(
        mapOf<Any?, Any?>(NSFileProtectionKey to NSFileProtectionComplete),
        ofItemAtPath = path,
        error = null
    )

    cachedDeviceKey = keyB64
    return keyB64
}

@OptIn(ExperimentalForeignApi::class)
private fun getDeviceKeyPath(): String {
    val docDir = NSFileManager.defaultManager.URLForDirectory(
        directory = NSDocumentDirectory,
        inDomain = NSUserDomainMask,
        appropriateForURL = null,
        create = false,
        error = null,
    ) ?: error("No Documents directory")
    return requireNotNull(docDir.path) + "/$KEY_FILE"
}

@OptIn(ExperimentalForeignApi::class)
actual fun encryptForStorage(plaintext: String): String {
    val keyB64 = getOrCreateDeviceKey()
    val result = SecureVaultCryptoCore.securevault_encrypt_field(keyB64, plaintext)
        ?: error("Rust encrypt_field returned null")
    val encrypted = result.toKString()
    SecureVaultCryptoCore.securevault_free_string(result)
    return encrypted
}

@OptIn(ExperimentalForeignApi::class)
actual fun decryptForStorage(ciphertext: String): String? {
    return try {
        val keyB64 = getOrCreateDeviceKey()
        val result = SecureVaultCryptoCore.securevault_decrypt_field(keyB64, ciphertext)
            ?: return null
        val plaintext = result.toKString()
        SecureVaultCryptoCore.securevault_free_string(result)
        plaintext
    } catch (e: Exception) {
        null
    }
}
