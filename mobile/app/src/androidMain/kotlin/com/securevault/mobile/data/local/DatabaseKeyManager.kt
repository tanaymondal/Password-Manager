package com.securevault.mobile.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom
import androidx.core.content.edit

class DatabaseKeyManager(private val context: Context) {

    companion object {
        private const val PREFS_NAME = "secure_vault_db_prefs"
        private const val KEY_DB_PASSPHRASE = "db_passphrase"
        private const val PASSPHRASE_LENGTH = 32
    }

    private var encryptedPrefs: SharedPreferences? = null

    private fun getPrefs(): SharedPreferences {
        var prefs = encryptedPrefs
        if (prefs == null) {
            prefs = createEncryptedPrefs()
            encryptedPrefs = prefs
        }
        return prefs
    }

    private fun createEncryptedPrefs(): SharedPreferences {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .apply()
            context.deleteSharedPreferences(PREFS_NAME)
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }
    }

    fun getOrCreatePassphrase(): ByteArray {
        val prefs = getPrefs()
        val storedPassphrase = prefs.getString(KEY_DB_PASSPHRASE, null)

        return if (storedPassphrase != null) {
            try {
                android.util.Base64.decode(storedPassphrase, android.util.Base64.NO_WRAP)
            } catch (e: IllegalArgumentException) {
                prefs.edit { remove(KEY_DB_PASSPHRASE) }
                val newPassphrase = generateSecurePassphrase()
                val encoded = android.util.Base64.encodeToString(newPassphrase, android.util.Base64.NO_WRAP)
                prefs.edit { putString(KEY_DB_PASSPHRASE, encoded) }
                newPassphrase
            }
        } else {
            val newPassphrase = generateSecurePassphrase()
            val encoded = android.util.Base64.encodeToString(newPassphrase, android.util.Base64.NO_WRAP)
            prefs.edit { putString(KEY_DB_PASSPHRASE, encoded) }
            newPassphrase
        }
    }

    private fun generateSecurePassphrase(): ByteArray {
        val random = SecureRandom()
        val passphrase = ByteArray(PASSPHRASE_LENGTH)
        random.nextBytes(passphrase)
        return passphrase
    }

    fun clearPassphrase() {
        getPrefs().edit { clear() }
    }
}