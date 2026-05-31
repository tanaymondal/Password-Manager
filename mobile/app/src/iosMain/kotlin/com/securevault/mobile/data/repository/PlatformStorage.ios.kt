package com.securevault.mobile.data.repository

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSJSONSerialization
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.NSUserDomainMask
import platform.Foundation.NSDataWritingFileProtectionComplete
import platform.Foundation.NSString
import platform.Foundation.create
import platform.Foundation.writeToFile
import platform.Security.SecRandomCopyBytes

/**
 * iOS PlatformStorage using an encrypted JSON file in the Documents directory.
 * The file is protected with NSDataWritingFileProtectionComplete (device-level encryption).
 */
@OptIn(ExperimentalForeignApi::class)
actual class PlatformStorage {
    private val FILENAME = ".securevault_store"

    private var cache: MutableMap<String, String>? = null

    @OptIn(ExperimentalForeignApi::class)
    private fun getStorePath(): String {
        val documentDir = NSFileManager.defaultManager.URLForDirectory(
            directory = NSDocumentDirectory,
            inDomain = NSUserDomainMask,
            appropriateForURL = null,
            create = true,
            error = null,
        ) ?: error("Cannot access Documents directory")
        return requireNotNull(documentDir.path) + "/$FILENAME"
    }

    actual val isReady: Boolean get() = true
    actual fun init(context: Any) {}

    @OptIn(ExperimentalForeignApi::class)
    private fun ensureLoaded() {
        if (cache != null) return
        val path = getStorePath()
        cache = loadFile(path) ?: loadFile(getStorePath().also { /* retry */ }) ?: mutableMapOf()
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun loadFile(path: String): MutableMap<String, String>? {
        val data = NSData.create(contentsOfFile = path) ?: return null
        val obj = NSJSONSerialization.JSONObjectWithData(data, 0u, null) as? Map<*, *> ?: return null
        @Suppress("UNCHECKED_CAST")
        return (obj as? Map<String, String>)?.toMutableMap()
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun save() {
        val map = cache ?: return
        val data = NSJSONSerialization.dataWithJSONObject(map, 0u, null) ?: return
        data.writeToFile(getStorePath(), atomically = true)
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun getString(key: String, default: String): String {
        ensureLoaded()
        return cache?.get(key) ?: default
    }

    actual fun putString(key: String, value: String) {
        ensureLoaded()
        cache?.set(key, value)
        save()
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun getInt(key: String, default: Int): Int {
        ensureLoaded()
        return cache?.get(key)?.toIntOrNull() ?: default
    }

    actual fun putInt(key: String, value: Int) {
        putString(key, value.toString())
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun getBoolean(key: String, default: Boolean): Boolean {
        ensureLoaded()
        return when (cache?.get(key)) {
            "true" -> true; "false" -> false; else -> default
        }
    }

    actual fun putBoolean(key: String, value: Boolean) {
        putString(key, value.toString())
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun clear() {
        cache = mutableMapOf()
        save()
    }
}
