package com.securevault.mobile.data.repository

object SessionManager {
    val storage = PlatformStorage()

    fun getAccessToken(): String = storage.getString("sv_at", "")
    fun setAccessToken(value: String) { storage.putString("sv_at", value) }
    fun getRefreshToken(): String = storage.getString("sv_rt", "")
    fun setRefreshToken(value: String) { storage.putString("sv_rt", value) }
    fun getEncryptionSalt(): String = storage.getString("sv_es", "")
    fun setEncryptionSalt(value: String) { storage.putString("sv_es", value) }
    fun getAuthSalt(): String = storage.getString("sv_as", "")
    fun setAuthSalt(value: String) { storage.putString("sv_as", value) }
    fun getUserId(): String = storage.getString("sv_uid", "")
    fun setUserId(value: String) { storage.putString("sv_uid", value) }
    fun getUserEmail(): String = storage.getString("sv_em", "")
    fun setUserEmail(value: String) { storage.putString("sv_em", value) }
    fun getEncryptionVersion(): Int = storage.getInt("sv_ev", 2)
    fun setEncryptionVersion(value: Int) { storage.putInt("sv_ev", value) }
    fun getWrappedVaultKey(): String = storage.getString("sv_wvk", "")
    fun setWrappedVaultKey(value: String) { storage.putString("sv_wvk", value) }
    fun getDeviceId(): String = storage.getString("sv_did", "")
    fun setDeviceId(value: String) { storage.putString("sv_did", value) }
    fun getBiometricEnabled(): Boolean = storage.getBoolean("sv_be", false)
    fun setBiometricEnabled(value: Boolean) { storage.putBoolean("sv_be", value) }
    fun getKdfIterations(): Int = storage.getInt("sv_ki", 4)
    fun setKdfIterations(value: Int) { storage.putInt("sv_ki", value) }
    fun getKdfMemory(): Int = storage.getInt("sv_km", 65536)
    fun setKdfMemory(value: Int) { storage.putInt("sv_km", value) }
    fun getKdfParallelism(): Int = storage.getInt("sv_kp", 4)
    fun setKdfParallelism(value: Int) { storage.putInt("sv_kp", value) }
    fun getSecurityVersion(): String = storage.getString("sv_secv", "")
    fun setSecurityVersion(value: String) { storage.putString("sv_secv", value) }
    val isLoggedIn: Boolean get() = getAccessToken().isNotEmpty()
    fun clearSession() { storage.clear() }
}
