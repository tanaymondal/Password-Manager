package com.securevault.mobile.data.local

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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

    private val masterKey: MasterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private val encryptedPrefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun getOrCreatePassphrase(): ByteArray {
        val storedPassphrase = encryptedPrefs.getString(KEY_DB_PASSPHRASE, null)

        return if (storedPassphrase != null) {
            try {
                android.util.Base64.decode(storedPassphrase, android.util.Base64.NO_WRAP)
            } catch (e: IllegalArgumentException) {
                encryptedPrefs.edit { remove(KEY_DB_PASSPHRASE) }
                val newPassphrase = generateSecurePassphrase()
                val encoded = android.util.Base64.encodeToString(newPassphrase, android.util.Base64.NO_WRAP)
                encryptedPrefs.edit { putString(KEY_DB_PASSPHRASE, encoded) }
                newPassphrase
            }
        } else {
            val newPassphrase = generateSecurePassphrase()
            val encoded = android.util.Base64.encodeToString(newPassphrase, android.util.Base64.NO_WRAP)
            encryptedPrefs.edit { putString(KEY_DB_PASSPHRASE, encoded) }
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
        encryptedPrefs.edit { clear() }
    }
}