package com.securevault.mobile.data.repository

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

actual class PlatformStorage {
    private var prefs: SharedPreferences? = null
    private var appContext: Context? = null

    actual val isReady: Boolean get() = prefs != null

    actual fun init(context: Any) {
        if (context is Context) {
            appContext = context.applicationContext
            ensurePrefs()
        }
    }

    private fun ensurePrefs(): SharedPreferences {
        val existing = prefs
        if (existing != null) return existing
        val ctx = appContext ?: return createFallbackPrefs()
        return try {
            createEncryptedPrefs(ctx).also { prefs = it }
        } catch (e: Exception) {
            ctx.getSharedPreferences("sv_storage", Context.MODE_PRIVATE).also { prefs = it }
        }
    }

    private fun createEncryptedPrefs(ctx: Context): SharedPreferences {
        val mk = MasterKey.Builder(ctx)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            ctx, "sv_storage", mk,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun createFallbackPrefs(): SharedPreferences {
        // No context — return in-memory only (data lost on restart)
        return object : SharedPreferences {
            private val map = mutableMapOf<String, Any?>()
            override fun getAll() = map as Map<String, Any?>
            override fun getString(key: String?, def: String?) = (map[key] as? String) ?: def
            override fun getInt(key: String?, def: Int) = (map[key] as? Int) ?: def
            override fun getBoolean(key: String?, def: Boolean) = (map[key] as? Boolean) ?: def
            override fun edit() = object : SharedPreferences.Editor {
                override fun putString(key: String?, value: String?) = apply { if (value != null) map[key!!] = value else map.remove(key) }
                override fun putInt(key: String?, value: Int) = apply { map[key!!] = value }
                override fun putBoolean(key: String?, value: Boolean) = apply { map[key!!] = value }
                override fun putStringSet(key: String?, value: MutableSet<String?>?) = apply { map[key!!] = value }
                override fun putLong(key: String?, value: Long) = apply { map[key!!] = value }
                override fun putFloat(key: String?, value: Float) = apply { map[key!!] = value }
                override fun remove(key: String?) = apply { map.remove(key) }
                override fun clear() = apply { map.clear() }
                override fun apply() {}
                override fun commit() = true
            }
            override fun contains(key: String?) = map.containsKey(key)
            override fun getLong(key: String?, def: Long) = (map[key] as? Long) ?: def
            override fun getFloat(key: String?, def: Float) = (map[key] as? Float) ?: def
            override fun getStringSet(key: String?, def: MutableSet<String?>?) = (map[key] as? MutableSet<String?>) ?: def
            override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
            override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        }
    }

    actual fun getString(key: String, default: String): String =
        ensurePrefs().getString(key, default) ?: default

    actual fun putString(key: String, value: String) {
        ensurePrefs().edit().putString(key, value).apply()
    }

    actual fun getInt(key: String, default: Int): Int =
        ensurePrefs().getInt(key, default)

    actual fun putInt(key: String, value: Int) {
        ensurePrefs().edit().putInt(key, value).apply()
    }

    actual fun getBoolean(key: String, default: Boolean): Boolean =
        ensurePrefs().getBoolean(key, default)

    actual fun putBoolean(key: String, value: Boolean) {
        ensurePrefs().edit().putBoolean(key, value).apply()
    }

    actual fun clear() {
        ensurePrefs().edit().clear().apply()
    }
}
