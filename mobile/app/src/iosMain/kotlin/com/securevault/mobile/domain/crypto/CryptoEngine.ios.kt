package com.securevault.mobile.domain.crypto

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.get
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA1
import platform.CoreCrypto.CC_SHA1_DIGEST_LENGTH
import platform.Foundation.NSData
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.base64EncodedStringWithOptions
import platform.Foundation.create
import platform.Security.SecRandomCopyBytes

@OptIn(ExperimentalForeignApi::class)
actual class CryptoEngine {

    actual fun generateSalt(): String {
        val bytes = ByteArray(16)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 16uL, pinned.addressOf(0)) }
        return bytes.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = 16uL).base64EncodedStringWithOptions(0u)
        }
    }

    actual fun generateAuthHash(
        password: String, salt: String, iterations: Int, memory: Int, parallelism: Int
    ): String {
        val mkB64 = SecureVaultCryptoCore.securevault_derive_master_key(password, salt, iterations, memory, parallelism)
            ?: error("Rust deriveMasterKey returned null")
        val result = SecureVaultCryptoCore.securevault_derive_auth_hash(mkB64.toKString())
            ?: error("Rust deriveAuthHash returned null")
        return result.toKString()
    }

    actual fun generateVaultKey(): String {
        val bytes = ByteArray(32)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 32uL, pinned.addressOf(0)) }
        return bytes.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = 32uL).base64EncodedStringWithOptions(0u)
        }
    }

    actual fun deriveKek(
        password: String, encryptionSalt: String, iterations: Int, memory: Int, parallelism: Int
    ): ByteArray {
        val mkB64 = SecureVaultCryptoCore.securevault_derive_master_key(password, encryptionSalt, iterations, memory, parallelism)
            ?: error("Rust deriveMasterKey returned null")
        val kekB64 = SecureVaultCryptoCore.securevault_derive_kek(mkB64.toKString())
            ?: error("Rust deriveKek returned null")
        val data = NSData.create(base64EncodedString = kekB64.toKString(), options = 0u) ?: return ByteArray(0)
        return ByteArray(data.length.toInt()).apply {
            val ptr = data.bytes!!.reinterpret<ByteVar>()
            var idx = 0; while (idx < size) { this.set(idx, ptr.get(idx)); idx++ }
        }
    }

    actual fun wrapVaultKey(vaultKey: String, kek: ByteArray): String {
        val kekB64 = kek.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = kek.size.toULong()).base64EncodedStringWithOptions(0u)
        }
        val result = SecureVaultCryptoCore.securevault_wrap_vault_key(kekB64, vaultKey)
            ?: error("Rust wrapVaultKey returned null")
        return result.toKString()
    }

    actual fun unwrapVaultKey(wrappedVaultKey: String, kek: ByteArray): String {
        val kekB64 = kek.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = kek.size.toULong()).base64EncodedStringWithOptions(0u)
        }
        val result = SecureVaultCryptoCore.securevault_unwrap_vault_key(kekB64, wrappedVaultKey)
            ?: error("Rust unwrapVaultKey returned null")
        return result.toKString()
    }

    actual fun sha1Hex(data: String): String {
        val digest = ByteArray(CC_SHA1_DIGEST_LENGTH.toInt())
        val input = data.encodeToByteArray()
        digest.usePinned { pinned ->
            input.usePinned { inp ->
                CC_SHA1(inp.addressOf(0), input.size.toUInt(), pinned.addressOf(0).reinterpret())
            }
        }
        return digest.joinToString("") { it.toString(16).padStart(2, '0') }.uppercase()
    }

    actual fun generateSecureDeviceId(): String {
        val bytes = ByteArray(16)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 16uL, pinned.addressOf(0)) }
        return bytes.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    }
}
