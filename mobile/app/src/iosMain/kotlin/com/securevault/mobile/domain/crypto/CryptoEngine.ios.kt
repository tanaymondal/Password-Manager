package com.securevault.mobile.domain.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.Foundation.*
import platform.Security.SecRandomCopyBytes

actual class CryptoEngine {
    private val keyLength = 32uL

    @OptIn(ExperimentalForeignApi::class)
    actual fun generateSalt(): String {
        val bytes = ByteArray(16)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 16, pinned.addressOf(0)) }
        return bytes.toNSData().base64EncodedStringWithOptions(0u)
    }

    actual fun generateAuthHash(
        password: String,
        salt: String,
        iterations: Int,
        memory: Int,
        parallelism: Int
    ): String {
        val hash = deriveKey(password, salt, iterations, memory, parallelism)
        return hash.toNSData().base64EncodedStringWithOptions(0u)
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun generateVaultKey(): String {
        val bytes = ByteArray(32)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 32, pinned.addressOf(0)) }
        return bytes.toNSData().base64EncodedStringWithOptions(0u)
    }

    actual fun deriveKek(
        password: String,
        encryptionSalt: String,
        iterations: Int,
        memory: Int,
        parallelism: Int
    ): ByteArray {
        return deriveKey(password, encryptionSalt, iterations, memory, parallelism)
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun deriveKey(
        password: String,
        saltBase64: String,
        iterations: Int,
        memory: Int,
        parallelism: Int
    ): ByteArray {
        val salt = NSData.create(base64EncodedString = saltBase64, options = 0u) ?: NSData()
        val passwordData = (password as NSString).dataUsingEncoding(NSUTF8StringEncoding) ?: NSData()
        val keyBytes = ByteArray(keyLength.toInt())
        keyBytes.usePinned { keyPinned ->
            passwordData.bytes!!.reinterpret<UByteVar>().let { passBytes ->
                CCKeyDerivationPBKDF(
                    kCCPBKDF2,
                    passBytes,
                    passwordData.length,
                    salt.bytes,
                    salt.length,
                    kCCPRFHmacAlgSHA256,
                    iterations.toUInt(),
                    keyPinned.addressOf(0),
                    keyLength
                )
            }
        }
        return keyBytes
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun wrapVaultKey(vaultKey: String, kek: ByteArray): String {
        val vaultKeyData = NSData.create(base64EncodedString = vaultKey, options = 0u) ?: NSData()
        val iv = ByteArray(12)
        iv.usePinned { pinned -> SecRandomCopyBytes(null, 12, pinned.addressOf(0)) }

        val ciphertextLen = vaultKeyData.length + 16uL
        val ciphertext = ByteArray(ciphertextLen.toInt())
        var bytesWritten = 0uL

        kek.usePinned { kekPinned ->
            iv.usePinned { ivPinned ->
                ciphertext.usePinned { outPinned ->
                    val status = CCCrypt(
                        kCCEncrypt,
                        kCCAlgorithmAES,
                        kCCOptionGCM,
                        kekPinned.addressOf(0),
                        keyLength,
                        ivPinned.addressOf(0),
                        vaultKeyData.bytes,
                        vaultKeyData.length,
                        outPinned.addressOf(0),
                        ciphertextLen,
                        bytesWritten.ptr
                    )
                    bytesWritten = bytesWritten.get()
                }
            }
        }

        val combined = ByteArray(12 + bytesWritten.toInt())
        iv.copyInto(combined)
        ciphertext.copyInto(combined, destinationOffset = 12)

        return combined.toNSData().base64EncodedStringWithOptions(0u)
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun unwrapVaultKey(wrappedVaultKey: String, kek: ByteArray): String {
        val combined = NSData.create(base64EncodedString = wrappedVaultKey, options = 0u) ?: NSData()
        val iv = ByteArray(12)
        combined.bytes!!.reinterpret<ByteVar>().let { ptr ->
            for (i in 0..11) iv[i] = ptr[i]
        }
        val ciphertextLen = combined.length - 12uL
        val ciphertext = ByteArray(ciphertextLen.toInt())
        combined.bytes!!.reinterpret<ByteVar>().let { ptr ->
            for (i in 0 until ciphertextLen.toInt()) ciphertext[i] = ptr[12 + i]
        }

        val plaintext = ByteArray(ciphertextLen.toInt())
        var bytesWritten = 0uL

        kek.usePinned { kekPinned ->
            iv.usePinned { ivPinned ->
                ciphertext.usePinned { ctPinned ->
                    plaintext.usePinned { outPinned ->
                        CCCrypt(
                            kCCDecrypt,
                            kCCAlgorithmAES,
                            kCCOptionGCM,
                            kekPinned.addressOf(0),
                            keyLength,
                            ivPinned.addressOf(0),
                            ctPinned.addressOf(0),
                            ciphertextLen,
                            outPinned.addressOf(0),
                            ciphertextLen,
                            bytesWritten.ptr
                        )
                    }
                }
            }
        }

        return plaintext.toNSData().base64EncodedStringWithOptions(0u)
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun sha1Hex(data: String): String {
        val digest = ByteArray(CC_SHA1_DIGEST_LENGTH.toInt())
        val input = (data as NSString).dataUsingEncoding(NSUTF8StringEncoding) ?: NSData()
        digest.usePinned { pinned ->
            CC_SHA1(input.bytes, CC_LONG(input.length.toDouble()), pinned.addressOf(0).reinterpret())
        }
        return digest.joinToString("") { "%02x".format(it) }.uppercase()
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun generateSecureDeviceId(): String {
        val bytes = ByteArray(16)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 16, pinned.addressOf(0)) }
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
