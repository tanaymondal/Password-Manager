package com.securevault.mobile.data.repository

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking

object SessionManager {
    private var _dataStore: DataStore<Preferences>? = null
    val dataStore: DataStore<Preferences> get() = _dataStore ?: error("DataStore not initialized")
    private var _dataStoreReady = false
    val isDataStoreReady: Boolean get() = _dataStoreReady

    fun initDataStore(store: DataStore<Preferences>) {
        _dataStore = store
        _dataStoreReady = true
    }

    private val KEY_AT = stringPreferencesKey("sv_at")
    private val KEY_RT = stringPreferencesKey("sv_rt")
    private val KEY_ES = stringPreferencesKey("sv_es")
    private val KEY_AS = stringPreferencesKey("sv_as")
    private val KEY_UID = stringPreferencesKey("sv_uid")
    private val KEY_EM = stringPreferencesKey("sv_em")
    private val KEY_EV = intPreferencesKey("sv_ev")
    private val KEY_WVK = stringPreferencesKey("sv_wvk")
    private val KEY_DID = stringPreferencesKey("sv_did")
    private val KEY_BE = booleanPreferencesKey("sv_be")
    private val KEY_KI = intPreferencesKey("sv_ki")
    private val KEY_KM = intPreferencesKey("sv_km")
    private val KEY_KP = intPreferencesKey("sv_kp")
    private val KEY_SECV = stringPreferencesKey("sv_secv")
    private val KEY_BIO_VK = stringPreferencesKey("sv_bio_vk")
    private val KEY_BIO_FAIL = intPreferencesKey("sv_bio_fail")

    fun getAccessToken(): String = read(KEY_AT, "")
    fun setAccessToken(value: String) { write(KEY_AT, value) }
    fun getRefreshToken(): String = read(KEY_RT, "")
    fun setRefreshToken(value: String) { write(KEY_RT, value) }
    fun getEncryptionSalt(): String = read(KEY_ES, "")
    fun setEncryptionSalt(value: String) { write(KEY_ES, value) }
    fun getAuthSalt(): String = read(KEY_AS, "")
    fun setAuthSalt(value: String) { write(KEY_AS, value) }
    fun getUserId(): String = read(KEY_UID, "")
    fun setUserId(value: String) { write(KEY_UID, value) }
    fun getUserEmail(): String = read(KEY_EM, "")
    fun setUserEmail(value: String) { write(KEY_EM, value) }
    fun getEncryptionVersion(): Int = read(KEY_EV, 2)
    fun setEncryptionVersion(value: Int) { write(KEY_EV, value) }
    fun getWrappedVaultKey(): String = read(KEY_WVK, "")
    fun setWrappedVaultKey(value: String) { write(KEY_WVK, value) }
    fun getDeviceId(): String = read(KEY_DID, "")
    fun setDeviceId(value: String) { write(KEY_DID, value) }
    fun getBiometricEnabled(): Boolean = read(KEY_BE, false)
    fun setBiometricEnabled(value: Boolean) { write(KEY_BE, value) }
    fun getKdfIterations(): Int = read(KEY_KI, 4)
    fun setKdfIterations(value: Int) { write(KEY_KI, value) }
    fun getKdfMemory(): Int = read(KEY_KM, 65536)
    fun setKdfMemory(value: Int) { write(KEY_KM, value) }
    fun getKdfParallelism(): Int = read(KEY_KP, 4)
    fun setKdfParallelism(value: Int) { write(KEY_KP, value) }
    fun getSecurityVersion(): String = read(KEY_SECV, "")
    fun setSecurityVersion(value: String) { write(KEY_SECV, value) }
    fun getBiometricVaultKey(): String = read(KEY_BIO_VK, "")
    fun setBiometricVaultKey(value: String) { write(KEY_BIO_VK, value) }
    fun getBiometricFailureCount(): Int = read(KEY_BIO_FAIL, 0)
    fun setBiometricFailureCount(value: Int) { write(KEY_BIO_FAIL, value) }

    val isLoggedIn: Boolean get() = getAccessToken().isNotEmpty()

    fun clearSession() {
        runBlocking { dataStore.edit { it.clear() } }
    }

    private fun read(key: Preferences.Key<String>, default: String): String =
        runBlocking { dataStore.data.first()[key] ?: default }

    private fun read(key: Preferences.Key<Int>, default: Int): Int =
        runBlocking { dataStore.data.first()[key] ?: default }

    private fun read(key: Preferences.Key<Boolean>, default: Boolean): Boolean =
        runBlocking { dataStore.data.first()[key] ?: default }

    private fun write(key: Preferences.Key<String>, value: String) {
        runBlocking { dataStore.edit { it[key] = value } }
    }

    private fun write(key: Preferences.Key<Int>, value: Int) {
        runBlocking { dataStore.edit { it[key] = value } }
    }

    private fun write(key: Preferences.Key<Boolean>, value: Boolean) {
        runBlocking { dataStore.edit { it[key] = value } }
    }
}
