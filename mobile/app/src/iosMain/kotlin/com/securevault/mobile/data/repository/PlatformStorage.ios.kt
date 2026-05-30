package com.securevault.mobile.data.repository

import platform.Foundation.NSUserDefaults

actual class PlatformStorage {
    private val prefs = NSUserDefaults.standardUserDefaults

    actual val isReady: Boolean get() = true
    actual fun init(context: Any) {}

    actual fun getString(key: String, default: String): String =
        prefs.stringForKey(key) ?: default

    actual fun putString(key: String, value: String) {
        prefs.setObject(value, forKey = key)
    }

    actual fun getInt(key: String, default: Int): Int =
        prefs.integerForKey(key).toInt().coerceAtLeast(default)

    actual fun putInt(key: String, value: Int) {
        prefs.setInteger(value.toLong(), forKey = key)
    }

    actual fun getBoolean(key: String, default: Boolean): Boolean =
        if (prefs.objectForKey(key) != null) prefs.boolForKey(key) else default

    actual fun putBoolean(key: String, value: Boolean) {
        prefs.setBool(value, forKey = key)
    }

    actual fun clear() {
        val dict = prefs.dictionaryRepresentation()
        for (key in dict.keys) {
            prefs.removeObjectForKey(key as String)
        }
    }
}
