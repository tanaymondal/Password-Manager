package com.securevault.mobile.domain.crypto

import android.util.Base64

object RustCryptoCore {
    private var loaded = false

    fun ensureLoaded(libraryPath: String? = null) {
        if (!loaded) {
            if (libraryPath != null) {
                System.load(libraryPath)
            } else {
                System.loadLibrary("securevault_crypto_core")
            }
            loaded = true
        }
    }

    private external fun nativeDeriveMasterKey(
        password: String,
        saltB64: String,
        iterations: Int,
        memory: Int,
        parallelism: Int
    ): String?

    private external fun nativeDeriveAuthHash(
        masterKeyB64: String
    ): String?

    private external fun nativeDeriveKek(
        masterKeyB64: String
    ): String?

    fun deriveMasterKey(
        password: String,
        saltB64: String,
        iterations: Int = 3,
        memory: Int = 98304,
        parallelism: Int = 4
    ): ByteArray {
        ensureLoaded()
        val b64 = nativeDeriveMasterKey(password, saltB64, iterations, memory, parallelism)
            ?: throw RuntimeException("Rust deriveMasterKey failed")
        return Base64.decode(b64, Base64.DEFAULT)
    }

    fun deriveAuthHash(
        masterKey: ByteArray
    ): String {
        ensureLoaded()
        val mkB64 = Base64.encodeToString(masterKey, Base64.NO_WRAP)
        return nativeDeriveAuthHash(mkB64)
            ?: throw RuntimeException("Rust deriveAuthHash failed")
    }

    fun deriveKek(
        masterKey: ByteArray
    ): ByteArray {
        ensureLoaded()
        val mkB64 = Base64.encodeToString(masterKey, Base64.NO_WRAP)
        val b64 = nativeDeriveKek(mkB64)
            ?: throw RuntimeException("Rust deriveKek failed")
        return Base64.decode(b64, Base64.DEFAULT)
    }
}
