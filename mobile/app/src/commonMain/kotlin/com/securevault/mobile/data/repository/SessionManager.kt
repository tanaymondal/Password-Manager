package com.securevault.mobile.data.repository

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object SessionManager {
    private const val PREFS_NAME = "secure_vault_session"
    private const val PREFS_ENCRYPTED_NAME = "secure_vault_session_encrypted"
    private const val KEY_ACCESS_TOKEN = "access_token"
    private const val KEY_REFRESH_TOKEN = "refresh_token"
    private const val KEY_ENCRYPTION_SALT = "encryption_salt"
    private const val KEY_USER_ID = "user_id"
    private const val KEY_USER_EMAIL = "user_email"
    private const val KEY_ENCRYPTION_VERSION = "encryption_version"
    private const val KEY_WRAPPED_VAULT_KEY = "wrapped_vault_key"

    private var encryptedPrefs: SharedPreferences? = null
    private var appContext: Context? = null

    fun init(context: Context) {
        appContext = context.applicationContext
        if (encryptedPrefs == null) {
            try {
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()
                encryptedPrefs = EncryptedSharedPreferences.create(
                    context,
                    PREFS_ENCRYPTED_NAME,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
            } catch (e: Exception) {
                context.getSharedPreferences(PREFS_ENCRYPTED_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .clear()
                    .apply()
                context.deleteSharedPreferences(PREFS_ENCRYPTED_NAME)
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()
                encryptedPrefs = EncryptedSharedPreferences.create(
                    context,
                    PREFS_ENCRYPTED_NAME,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
            }
        }
    }

    fun getAccessToken(): String = encryptedPrefs?.getString(KEY_ACCESS_TOKEN, "") ?: ""

    fun setAccessToken(value: String) {
        encryptedPrefs?.edit()?.putString(KEY_ACCESS_TOKEN, value)?.apply()
    }

    fun getRefreshToken(): String = encryptedPrefs?.getString(KEY_REFRESH_TOKEN, "") ?: ""

    fun setRefreshToken(value: String) {
        encryptedPrefs?.edit()?.putString(KEY_REFRESH_TOKEN, value)?.apply()
    }

    fun getEncryptionSalt(): String = encryptedPrefs?.getString(KEY_ENCRYPTION_SALT, "") ?: ""

    fun setEncryptionSalt(value: String) {
        encryptedPrefs?.edit()?.putString(KEY_ENCRYPTION_SALT, value)?.apply()
    }

    fun getUserId(): String = encryptedPrefs?.getString(KEY_USER_ID, "") ?: ""

    fun setUserId(value: String) {
        encryptedPrefs?.edit()?.putString(KEY_USER_ID, value)?.apply()
    }

    fun getUserEmail(): String = encryptedPrefs?.getString(KEY_USER_EMAIL, "") ?: ""

    fun setUserEmail(value: String) {
        encryptedPrefs?.edit()?.putString(KEY_USER_EMAIL, value)?.apply()
    }

    fun getEncryptionVersion(): Int = encryptedPrefs?.getInt(KEY_ENCRYPTION_VERSION, 2) ?: 2

    fun setEncryptionVersion(value: Int) {
        encryptedPrefs?.edit()?.putInt(KEY_ENCRYPTION_VERSION, value)?.apply()
    }

    fun getWrappedVaultKey(): String = encryptedPrefs?.getString(KEY_WRAPPED_VAULT_KEY, "") ?: ""

    fun setWrappedVaultKey(value: String) {
        encryptedPrefs?.edit()?.putString(KEY_WRAPPED_VAULT_KEY, value)?.apply()
    }

    val isLoggedIn: Boolean
        get() = getAccessToken().isNotEmpty()

    fun clearSession() {
        encryptedPrefs?.edit()?.clear()?.apply()
        clearLocalDatabase()
    }

    private fun clearLocalDatabase() {
        val context = appContext ?: return
        context.deleteDatabase("secure_vault.db")
        context.getSharedPreferences("secure_vault_db_prefs", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .apply()
        context.deleteSharedPreferences("secure_vault_db_prefs")
    }
}
