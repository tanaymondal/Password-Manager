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

    private external fun nativeDeriveAuthHash(
        password: String,
        salt: String,
        iterations: Int,
        memory: Int,
        parallelism: Int
    ): String?

    private external fun nativeDeriveKek(
        password: String,
        saltB64: String,
        iterations: Int,
        memory: Int,
        parallelism: Int
    ): String?

    fun deriveAuthHash(
        password: String,
        salt: String,
        iterations: Int = 3,
        memory: Int = 98304,
        parallelism: Int = 4
    ): String {
        ensureLoaded()
        return nativeDeriveAuthHash(password, salt, iterations, memory, parallelism)
            ?: throw RuntimeException("Rust deriveAuthHash failed")
    }

    fun deriveKek(
        password: String,
        saltB64: String,
        iterations: Int = 3,
        memory: Int = 98304,
        parallelism: Int = 4
    ): ByteArray {
        ensureLoaded()
        val b64 = nativeDeriveKek(password, saltB64, iterations, memory, parallelism)
            ?: throw RuntimeException("Rust deriveKek failed")
        return Base64.decode(b64, Base64.DEFAULT)
    }
}
