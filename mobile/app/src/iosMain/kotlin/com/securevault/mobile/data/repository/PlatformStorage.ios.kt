@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
package com.securevault.mobile.data.repository

import kotlinx.cinterop.toKString
import platform.Security.errSecSuccess
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ByteVar

@OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
actual class PlatformStorage {
    private val service = "com.securevault"

    actual val isReady: Boolean get() = true
    actual fun init(context: Any) {}

    actual fun getString(key: String, default: String): String = readSec(key) ?: default
    actual fun putString(key: String, value: String) { writeSec(key, value) }
    actual fun getInt(key: String, default: Int): Int = readSec(key)?.toIntOrNull() ?: default
    actual fun putInt(key: String, value: Int) { writeSec(key, value.toString()) }
    actual fun getBoolean(key: String, default: Boolean): Boolean = when (readSec(key)) {
        "true" -> true; "false" -> false; else -> default
    }
    actual fun putBoolean(key: String, value: Boolean) { writeSec(key, value.toString()) }

    actual fun clear() {
        KeychainHelper.keychain_clear(service)
    }

    private fun readSec(key: String): String? {
        val ptr = KeychainHelper.keychain_read(service, key) ?: return null
        val result = ptr.toKString()
        KeychainHelper.keychain_free_string(ptr)
        return result
    }

    private fun writeSec(key: String, value: String) {
        KeychainHelper.keychain_write(service, key, value)
    }
}
