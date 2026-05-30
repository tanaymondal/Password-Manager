package com.securevault.mobile.data.local

class NativeBridge {
    companion object {
        @JvmStatic external fun nativeDeriveMasterKey(
            password: String,
            saltB64: String,
            iterations: Int,
            memory: Int,
            parallelism: Int
        ): String?

        @JvmStatic external fun nativeDeriveAuthHash(
            masterKeyB64: String
        ): String?

        @JvmStatic external fun nativeDeriveKek(
            masterKeyB64: String
        ): String?
    }
}
