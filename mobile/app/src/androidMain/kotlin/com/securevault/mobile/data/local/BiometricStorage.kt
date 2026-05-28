package com.securevault.mobile.data.local

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class BiometricStorage(private val context: Context) {
    companion object {
        private const val KEY_ALIAS = "secure_vault_biometric_key"
        private const val PREFS_NAME = "secure_vault_biometric"
        private const val KEY_IV = "biometric_iv"
        private const val KEY_ENCRYPTED_DATA = "biometric_encrypted_vault_key"
        private const val KEY_FAILURE_COUNT = "biometric_failure_count"
        private const val MAX_BIOMETRIC_FAILURES = 5
    }

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun isAvailable(): Boolean {
        return BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun hasEncryptedVaultKey(): Boolean {
        return prefs.contains(KEY_ENCRYPTED_DATA) && prefs.contains(KEY_IV)
    }

    fun isLockedOut(): Boolean {
        return prefs.getInt(KEY_FAILURE_COUNT, 0) >= MAX_BIOMETRIC_FAILURES
    }

    fun recordFailure() {
        val count = prefs.getInt(KEY_FAILURE_COUNT, 0) + 1
        prefs.edit().putInt(KEY_FAILURE_COUNT, count).apply()
        if (count >= MAX_BIOMETRIC_FAILURES) {
            clear()
        }
    }

    fun resetFailureCount() {
        prefs.edit().remove(KEY_FAILURE_COUNT).apply()
    }

    fun getEncryptionCipher(): Cipher? {
        return try {
            val secretKey = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            cipher
        } catch (e: Exception) {
            null
        }
    }

    fun getDecryptionCipher(): Cipher? {
        return try {
            val ivString = prefs.getString(KEY_IV, null) ?: return null
            val secretKey = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = Base64.decode(ivString, Base64.NO_WRAP)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            cipher
        } catch (e: Exception) {
            null
        }
    }

    fun onEncryptComplete(cipher: Cipher, vaultKey: String): Boolean {
        return try {
            val encrypted = cipher.doFinal(vaultKey.toByteArray(Charsets.UTF_8))
            val iv = cipher.iv
            prefs.edit()
                .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                .putString(KEY_ENCRYPTED_DATA, Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .apply()
            true
        } catch (e: Exception) {
            false
        }
    }

    fun onDecryptComplete(cipher: Cipher): String? {
        return try {
            val encryptedData = prefs.getString(KEY_ENCRYPTED_DATA, null)
                ?: return null
            val decrypted = cipher.doFinal(Base64.decode(encryptedData, Base64.NO_WRAP))
            resetFailureCount()
            String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    fun showBiometricPrompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        cipher: Cipher?,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit,
        onCancel: () -> Unit = {}
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                resetFailureCount()
                val authenticatedCipher = result.cryptoObject?.cipher
                if (authenticatedCipher != null) {
                    onSuccess(authenticatedCipher)
                } else if (cipher != null) {
                    onSuccess(cipher)
                } else {
                    onError("Authentication failed: no cipher available")
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                ) {
                    onCancel()
                } else {
                    recordFailure()
                    onError(errString.toString())
                }
            }

            override fun onAuthenticationFailed() {
                recordFailure()
                onError("Biometric authentication failed. Try again.")
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()

        if (cipher != null) {
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } else {
            prompt.authenticate(promptInfo)
        }
    }

    fun clear() {
        prefs.edit()
            .remove(KEY_IV)
            .remove(KEY_ENCRYPTED_DATA)
            .remove(KEY_FAILURE_COUNT)
            .apply()
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    private fun getOrCreateKey(): SecretKey {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        }
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(-1)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }
}
