package com.securevault.mobile.data.local

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.securevault.mobile.ui.PlatformContext
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

actual class BiometricStorage actual constructor(context: PlatformContext) {
    companion object {
        private const val KEY_ALIAS = "secure_vault_biometric_key"
        private const val PREFS_NAME = "secure_vault_biometric"
        private const val KEY_IV = "biometric_iv"
        private const val KEY_ENCRYPTED_DATA = "biometric_encrypted_vault_key"
        private const val KEY_FAILURE_COUNT = "biometric_failure_count"
        private const val MAX_BIOMETRIC_FAILURES = 5
    }

    private val appContext = context.androidContext
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    // Cached cipher from successful authentication — used by store/retrieve
    private var authorizedCipher: Cipher? = null

    actual fun isAvailable(): Boolean {
        return BiometricManager.from(appContext).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    actual fun hasEncryptedVaultKey(): Boolean {
        return prefs.contains(KEY_ENCRYPTED_DATA) && prefs.contains(KEY_IV)
    }

    actual fun isLockedOut(): Boolean {
        return prefs.getInt(KEY_FAILURE_COUNT, 0) >= MAX_BIOMETRIC_FAILURES
    }

    actual fun recordFailure() {
        val count = prefs.getInt(KEY_FAILURE_COUNT, 0) + 1
        prefs.edit().putInt(KEY_FAILURE_COUNT, count).apply()
        if (count >= MAX_BIOMETRIC_FAILURES) {
            clear()
        }
    }

    actual fun resetFailureCount() {
        prefs.edit().remove(KEY_FAILURE_COUNT).apply()
    }

    actual fun shouldShowBiometricPrompt(): Boolean {
        return isAvailable() && hasEncryptedVaultKey() && !isLockedOut()
    }

    actual fun authenticate(
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
        onCancel: () -> Unit
    ) {
        Log.d("BiometricStorage", "authenticate() called, appContext: ${appContext::class.simpleName}")
        val activity = appContext as? FragmentActivity ?: run {
            Log.w("BiometricStorage", "appContext is not FragmentActivity: ${appContext::class.simpleName}")
            onError("Activity not available")
            return
        }
        val executor = ContextCompat.getMainExecutor(appContext)

        Log.d("BiometricStorage", "Getting cipher...")
        val cipher = getDecryptionCipher() ?: getEncryptionCipher() ?: run {
            Log.w("BiometricStorage", "Failed to create cipher")
            onError("Failed to prepare crypto")
            return
        }
        authorizedCipher = cipher
        Log.d("BiometricStorage", "Cipher created, showing biometric prompt...")

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                Log.d("BiometricStorage", "onAuthenticationSucceeded")
                authorizedCipher = result.cryptoObject?.cipher ?: cipher
                Log.d("BiometricStorage", "authorizedCipher set, calling onSuccess")
                resetFailureCount()
                onSuccess()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.w("BiometricStorage", "onAuthenticationError: code=$errorCode msg=$errString")
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
                Log.w("BiometricStorage", "onAuthenticationFailed")
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

        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    actual fun storeVaultKey(vaultKey: String): Boolean {
        return try {
            val cipher = authorizedCipher ?: return false
            Log.d("BiometricStorage", "storeVaultKey: doFinal...")
            val encrypted = cipher.doFinal(vaultKey.toByteArray(Charsets.UTF_8))
            val iv = cipher.iv
            prefs.edit()
                .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                .putString(KEY_ENCRYPTED_DATA, Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .apply()
            Log.d("BiometricStorage", "storeVaultKey: success")
            authorizedCipher = null
            true
        } catch (e: Throwable) {
            Log.w("BiometricStorage", "storeVaultKey failed: ${e.message}")
            false
        }
    }

    actual fun retrieveVaultKey(): String? {
        return try {
            val cipher = authorizedCipher ?: return null
            val encryptedData = prefs.getString(KEY_ENCRYPTED_DATA, null) ?: return null
            Log.d("BiometricStorage", "retrieveVaultKey: doFinal...")
            val decrypted = cipher.doFinal(Base64.decode(encryptedData, Base64.NO_WRAP))
            resetFailureCount()
            authorizedCipher = null
            String(decrypted, Charsets.UTF_8)
        } catch (e: Throwable) {
            Log.w("BiometricStorage", "retrieveVaultKey failed: ${e.message}")
            null
        }
    }

    actual fun clear() {
        prefs.edit()
            .remove(KEY_IV)
            .remove(KEY_ENCRYPTED_DATA)
            .remove(KEY_FAILURE_COUNT)
            .apply()
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
        authorizedCipher = null
    }

    private fun getOrCreateKey(): SecretKey? {
        try {
            if (keyStore.containsAlias(KEY_ALIAS)) {
                return (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
            }
        } catch (_: Exception) {}

        return try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
            keyGenerator.init(spec)
            keyGenerator.generateKey()
        } catch (e: Throwable) {
            Log.w("BiometricStorage", "Key creation failed (auth-required), trying without auth: ${e.message}")
            try {
                val keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
                )
                val spec = KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setUserAuthenticationRequired(false)
                    .build()
                keyGenerator.init(spec)
                keyGenerator.generateKey()
            } catch (e2: Throwable) {
                Log.e("BiometricStorage", "Key creation failed (no auth): ${e2.message}")
                null
            }
        }
    }

    private fun getEncryptionCipher(): Cipher? {
        return try {
            val secretKey = getOrCreateKey() ?: return null
            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            cipher
        } catch (e: Throwable) {
            Log.w("BiometricStorage", "getEncryptionCipher failed: ${e.message}")
            null
        }
    }

    private fun getDecryptionCipher(): Cipher? {
        return try {
            val ivString = prefs.getString(KEY_IV, null) ?: return null
            val secretKey = getOrCreateKey() ?: return null
            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
            val iv = Base64.decode(ivString, Base64.NO_WRAP)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            cipher
        } catch (e: Throwable) {
            null
        }
    }
}
