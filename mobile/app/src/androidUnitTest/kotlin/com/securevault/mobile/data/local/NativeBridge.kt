package com.securevault.mobile.data.local

class NativeBridge {
    companion object {
        @JvmStatic external fun nativeDeriveAuthHash(
            password: String,
            salt: String,
            iterations: Int,
            memory: Int,
            parallelism: Int
        ): String?

        @JvmStatic external fun nativeDeriveKek(
            password: String,
            saltB64: String,
            iterations: Int,
            memory: Int,
            parallelism: Int
        ): String?
    }
}
