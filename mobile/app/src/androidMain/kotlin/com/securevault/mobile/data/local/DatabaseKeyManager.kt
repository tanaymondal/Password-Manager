package com.securevault.mobile.data.local

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

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
            storedPassphrase.toByteArray(Charsets.UTF_8)
        } else {
            val newPassphrase = generateSecurePassphrase()
            encryptedPrefs.edit().putString(KEY_DB_PASSPHRASE, String(newPassphrase, Charsets.UTF_8)).apply()
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
        encryptedPrefs.edit().clear().apply()
    }
}