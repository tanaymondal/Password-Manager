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
    private const val KEY_MASTER_PASSWORD_HASH = "master_password_hash"
    private const val KEY_MASTER_PASSWORD = "master_password"

    private var encryptedPrefs: SharedPreferences? = null

    fun init(context: Context) {
        if (encryptedPrefs == null) {
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

    fun getMasterPasswordHash(): String = encryptedPrefs?.getString(KEY_MASTER_PASSWORD_HASH, "") ?: ""

    fun setMasterPasswordHash(value: String) {
        encryptedPrefs?.edit()?.putString(KEY_MASTER_PASSWORD_HASH, value)?.apply()
    }

    fun getMasterPassword(): String = encryptedPrefs?.getString(KEY_MASTER_PASSWORD, "") ?: ""

    fun setMasterPassword(value: String) {
        encryptedPrefs?.edit()?.putString(KEY_MASTER_PASSWORD, value)?.apply()
    }

    val isLoggedIn: Boolean
        get() = getAccessToken().isNotEmpty()

    fun clearSession() {
        encryptedPrefs?.edit()?.clear()?.apply()
    }
}
