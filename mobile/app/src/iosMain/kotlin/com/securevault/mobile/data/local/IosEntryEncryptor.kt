package com.securevault.mobile.data.local

import com.securevault.mobile.data.model.VaultEntryRequest
import com.securevault.mobile.data.model.VaultEntryResponse
import com.securevault.mobile.data.repository.EntryEncryptor
import com.securevault.mobile.data.repository.VaultKeyManager
import com.securevault.mobile.domain.model.VaultEntry
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.Foundation.*
import platform.Security.SecRandomCopyBytes

class IosEntryEncryptor : EntryEncryptor, VaultKeyManager {
    private val keyLength = 32uL
    private val gcmIvLength = 12
    private val entryVersionPrefix = "v1:"
    private var cachedVaultKey: ByteArray? = null

    @OptIn(ExperimentalForeignApi::class)
    override fun unlockVault(password: String, encryptionSalt: String, wrappedVaultKey: String) {
        if (wrappedVaultKey.isEmpty()) throw IllegalStateException("Wrapped vault key not available")
        val kek = deriveKek(password, encryptionSalt)
        val vaultKey = decryptWithKek(wrappedVaultKey, kek)
        cachedVaultKey = vaultKey
    }

    @OptIn(ExperimentalForeignApi::class)
    override fun wrapVaultKey(vaultKey: String, password: String, encryptionSalt: String): String {
        val kek = deriveKek(password, encryptionSalt)
        return encryptWithKek(vaultKey, kek)
    }

    @OptIn(ExperimentalForeignApi::class)
    override fun generateVaultKey(): String {
        val bytes = ByteArray(32)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 32, pinned.addressOf(0)) }
        cachedVaultKey = bytes.copyOf()
        return bytes.toNSData().base64EncodedStringWithOptions(0u)
    }

    @OptIn(ExperimentalForeignApi::class)
    override fun generateEncryptionSalt(): String {
        val bytes = ByteArray(16)
        bytes.usePinned { pinned -> SecRandomCopyBytes(null, 16, pinned.addressOf(0)) }
        return bytes.toNSData().base64EncodedStringWithOptions(0u)
    }

    override fun getCachedVaultKey(): String? {
        return cachedVaultKey?.toNSData()?.base64EncodedStringWithOptions(0u)
    }

    override fun setCachedVaultKey(key: String) {
        cachedVaultKey = (key as NSString).dataUsingEncoding(NSUTF8StringEncoding)?.let {
            ByteArray(it.length.toInt()).also { arr -> it.bytes!!.reinterpret<ByteVar>().let { p -> for (i in arr.indices) arr[i] = p[i] } }
        }
    }

    override fun clearCachedVaultKey() {
        cachedVaultKey?.fill(0)
        cachedVaultKey = null
    }

    @OptIn(ExperimentalForeignApi::class)
    override fun encrypt(entry: VaultEntry): VaultEntryRequest {
        val vaultKey = cachedVaultKey ?: throw IllegalStateException("Vault key not available")
        val iv = ByteArray(gcmIvLength)
        iv.usePinned { pinned -> SecRandomCopyBytes(null, gcmIvLength, pinned.addressOf(0)) }

        val plaintext = entry.toString()
        val plaintextData = (plaintext as NSString).dataUsingEncoding(NSUTF8StringEncoding) ?: NSData()
        val ciphertextLen = plaintextData.length + 16uL
        val ciphertext = ByteArray(ciphertextLen.toInt())

        vaultKey.usePinned { keyPinned ->
            iv.usePinned { ivPinned ->
                ciphertext.usePinned { outPinned ->
                    CCCrypt(
                        kCCEncrypt, kCCAlgorithmAES, kCCOptionGCM,
                        keyPinned.addressOf(0), keyLength,
                        ivPinned.addressOf(0),
                        plaintextData.bytes, plaintextData.length,
                        outPinned.addressOf(0), ciphertextLen,
                        ciphertextLen.ptr
                    )
                }
            }
        }

        val combined = ByteArray(gcmIvLength + ciphertext.size)
        iv.copyInto(combined)
        ciphertext.copyInto(combined, destinationOffset = gcmIvLength)

        val b64 = combined.toNSData().base64EncodedStringWithOptions(0u) ?: ""
        val encryptedData = entryVersionPrefix + b64
        val ivString = iv.toNSData().base64EncodedStringWithOptions(0u) ?: ""

        return VaultEntryRequest(id = null, encryptedData = encryptedData, iv = ivString)
    }

    @OptIn(ExperimentalForeignApi::class)
    override fun decrypt(response: VaultEntryResponse): VaultEntry {
        val vaultKey = cachedVaultKey ?: throw IllegalStateException("Vault key not available")
        val rawData = if (response.encryptedData.startsWith(entryVersionPrefix))
            response.encryptedData.substring(entryVersionPrefix.length) else response.encryptedData
        val combined = NSData.create(base64EncodedString = rawData, options = 0u) ?: NSData()

        val iv = ByteArray(gcmIvLength)
        combined.bytes!!.reinterpret<ByteVar>().let { ptr ->
            for (i in 0..11) iv[i] = ptr[i]
        }
        val ciphertextLen = combined.length - gcmIvLength
        val ciphertext = ByteArray(ciphertextLen.toInt())
        combined.bytes!!.reinterpret<ByteVar>().let { ptr ->
            for (i in 0 until ciphertextLen.toInt()) ciphertext[i] = ptr[gcmIvLength + i]
        }

        val plaintext = ByteArray(ciphertextLen.toInt())

        vaultKey.usePinned { keyPinned ->
            iv.usePinned { ivPinned ->
                ciphertext.usePinned { ctPinned ->
                    plaintext.usePinned { outPinned ->
                        CCCrypt(
                            kCCDecrypt, kCCAlgorithmAES, kCCOptionGCM,
                            keyPinned.addressOf(0), keyLength,
                            ivPinned.addressOf(0),
                            ctPinned.addressOf(0), ciphertextLen,
                            outPinned.addressOf(0), ciphertextLen,
                            ciphertextLen.ptr
                        )
                    }
                }
            }
        }

        val result = NSString.create(bytes = plaintext.toNSData().bytes, length = plaintext.size.toULong(), encoding = NSUTF8StringEncoding) ?: ""
        return VaultEntry(id = response.id.hashCode().toLong(), title = "", username = "", password = "")
    }

    override fun encryptField(plaintext: String): String {
        if (plaintext.isEmpty()) return ""
        val vaultKey = cachedVaultKey ?: throw IllegalStateException("Vault key not available")
        val iv = ByteArray(gcmIvLength)
        iv.usePinned { pinned -> SecRandomCopyBytes(null, gcmIvLength, pinned.addressOf(0)) }

        val data = (plaintext as NSString).dataUsingEncoding(NSUTF8StringEncoding) ?: NSData()
        val outLen = data.length + 16uL
        val ciphertext = ByteArray(outLen.toInt())

        vaultKey.usePinned { keyPinned ->
            iv.usePinned { ivPinned ->
                ciphertext.usePinned { outPinned ->
                    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionGCM,
                        keyPinned.addressOf(0), keyLength, ivPinned.addressOf(0),
                        data.bytes, data.length, outPinned.addressOf(0), outLen, outLen.ptr)
                }
            }
        }

        val combined = ByteArray(gcmIvLength + ciphertext.size)
        iv.copyInto(combined)
        ciphertext.copyInto(combined, destinationOffset = gcmIvLength)
        val b64 = combined.toNSData().base64EncodedStringWithOptions(0u) ?: ""
        return entryVersionPrefix + b64
    }

    override fun decryptField(ciphertext: String): String {
        if (ciphertext.isEmpty()) return ""
        val vaultKey = cachedVaultKey ?: throw IllegalStateException("Vault key not available")
        val raw = if (ciphertext.startsWith(entryVersionPrefix)) ciphertext.substring(entryVersionPrefix.length) else ciphertext
        val combined = NSData.create(base64EncodedString = raw, options = 0u) ?: NSData()
        val iv = ByteArray(gcmIvLength)
        combined.bytes!!.reinterpret<ByteVar>().let { ptr ->
            for (i in 0..11) iv[i] = ptr[i]
        }
        val ctLen = combined.length - gcmIvLength
        val ct = ByteArray(ctLen.toInt())
        combined.bytes!!.reinterpret<ByteVar>().let { ptr ->
            for (i in 0 until ctLen.toInt()) ct[i] = ptr[gcmIvLength + i]
        }
        val plaintext = ByteArray(ctLen.toInt())
        vaultKey.usePinned { kp ->
            iv.usePinned { ip -> ct.usePinned { cp -> plaintext.usePinned { op ->
                CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionGCM,
                    kp.addressOf(0), keyLength, ip.addressOf(0),
                    cp.addressOf(0), ctLen, op.addressOf(0), ctLen, ctLen.ptr)
            }}}
        }
        return (plaintext.toNSData() as NSData).let { NSString.create(bytes = it.bytes, length = it.length, encoding = NSUTF8StringEncoding) ?: "" }
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun deriveKek(password: String, encryptionSalt: String): ByteArray {
        val salt = NSData.create(base64EncodedString = encryptionSalt, options = 0u) ?: NSData()
        val passData = (password as NSString).dataUsingEncoding(NSUTF8StringEncoding) ?: NSData()
        val keyBytes = ByteArray(keyLength.toInt())
        keyBytes.usePinned { out ->
            CCKeyDerivationPBKDF(
                kCCPBKDF2, passData.bytes, passData.length,
                salt.bytes, salt.length, kCCPRFHmacAlgSHA256,
                600000u, out.addressOf(0), keyLength
            )
        }
        return keyBytes
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun encryptWithKek(dataBase64: String, kek: ByteArray): String {
        val data = NSData.create(base64EncodedString = dataBase64, options = 0u) ?: NSData()
        val iv = ByteArray(gcmIvLength)
        iv.usePinned { pinned -> SecRandomCopyBytes(null, gcmIvLength, pinned.addressOf(0)) }
        val outLen = data.length + 16uL
        val ciphertext = ByteArray(outLen.toInt())
        kek.usePinned { kp -> iv.usePinned { ip -> ciphertext.usePinned { op ->
            CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionGCM,
                kp.addressOf(0), keyLength, ip.addressOf(0),
                data.bytes, data.length, op.addressOf(0), outLen, outLen.ptr)
        }}}
        val result = ByteArray(gcmIvLength + ciphertext.size)
        iv.copyInto(result)
        ciphertext.copyInto(result, destinationOffset = gcmIvLength)
        return result.toNSData().base64EncodedStringWithOptions(0u)
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun decryptWithKek(wrappedBase64: String, kek: ByteArray): ByteArray {
        val combined = NSData.create(base64EncodedString = wrappedBase64, options = 0u) ?: NSData()
        val iv = ByteArray(gcmIvLength)
        combined.bytes!!.reinterpret<ByteVar>().let { ptr ->
            for (i in 0..11) iv[i] = ptr[i]
        }
        val ctLen = combined.length - gcmIvLength
        val ct = ByteArray(ctLen.toInt())
        combined.bytes!!.reinterpret<ByteVar>().let { ptr ->
            for (i in 0 until ctLen.toInt()) ct[i] = ptr[gcmIvLength + i]
        }
        val plaintext = ByteArray(ctLen.toInt())
        kek.usePinned { kp -> iv.usePinned { ip -> ct.usePinned { cp -> plaintext.usePinned { op ->
            CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionGCM,
                kp.addressOf(0), keyLength, ip.addressOf(0),
                cp.addressOf(0), ctLen, op.addressOf(0), ctLen, ctLen.ptr)
        }}}
        return plaintext
    }
}
