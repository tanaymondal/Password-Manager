package com.securevault.mobile.data.local

import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.Ignore
import java.util.Base64
import com.lambdapioneer.argon2kt.SoLoaderShim

class CryptoEngineTest {

    companion object {
        const val TEST_PASSWORD = "TestPassword123!"
        const val TEST_ENCRYPTION_SALT_BASE64 = "dGVzdEVuY3J5cHRpb25TYWx0MTIzNDU="
        const val TEST_VAULT_KEY_BASE64 = "dGVzdFZhdWx0S2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo="

        val testSoLoader: SoLoaderShim?
            get() = null
    }

    private lateinit var engine: CryptoEngine

    @Before
    fun setUp() {
        engine = CryptoEngine(
            getPassword = { TEST_PASSWORD },
            getEncryptionSalt = { TEST_ENCRYPTION_SALT_BASE64 },
            soLoaderShim = testSoLoader
        )
    }

    // ===== Pure Crypto Tests (JVM, no JNI required) =====

    @Test
    fun generateVaultKey_produces32ByteKey() {
        val vaultKey = engine.generateVaultKey()
        val vaultKeyBytes = Base64.getDecoder().decode(vaultKey)
        assertEquals("Vault key must be 32 bytes", 32, vaultKeyBytes.size)
    }

    @Test
    fun generateVaultKey_producesUniqueKeys() {
        val key1 = engine.generateVaultKey()
        val key2 = engine.generateVaultKey()
        assertNotEquals("Each generated vault key must be unique", key1, key2)
    }

    @Test
    fun generateVaultKey_producesValidBase64() {
        val vaultKey = engine.generateVaultKey()
        Base64.getDecoder().decode(vaultKey)
    }

    @Test
    fun vaultKey_is256bitForAES256() {
        val vaultKeyBytes = Base64.getDecoder().decode(TEST_VAULT_KEY_BASE64)
        assertEquals("Vault key must be 256 bits (32 bytes) for AES-256", 32, vaultKeyBytes.size)
    }

    @Test
    fun entryEncryption_decryptionRoundTrip() {
        val vaultKey = engine.generateVaultKey()
        engine.setCachedVaultKey(vaultKey)
        val (encryptedData, iv) = engine.encryptEntry(
            id = 123L, title = "Test Entry",
            username = "testuser@example.com",
            password = "supersecretpassword",
            url = "https://example.com",
            notes = "Test notes here",
            folder = "Work"
        )
        assertNotNull(encryptedData)
        assertNotNull(iv)
        assertNotEquals("Encrypted data must differ from plaintext",
            encryptedData, "123|Test Entry|testuser@example.com|supersecretpassword|...")
        val decrypted = engine.decryptEntry(encryptedData, iv)
        assertEquals("123", decrypted["id"])
        assertEquals("Test Entry", decrypted["title"])
        assertEquals("testuser@example.com", decrypted["username"])
        assertEquals("supersecretpassword", decrypted["password"])
        assertEquals("https://example.com", decrypted["url"])
        assertEquals("Test notes here", decrypted["notes"])
        assertEquals("Work", decrypted["folder"])
    }

    @Test
    fun entryEncryption_withEmptyOptionalFields() {
        val vaultKey = engine.generateVaultKey()
        engine.setCachedVaultKey(vaultKey)
        val (encryptedData, iv) = engine.encryptEntry(
            id = 456L, title = "Minimal Entry",
            username = "user", password = "pass",
            url = null, notes = null, folder = null
        )
        val decrypted = engine.decryptEntry(encryptedData, iv)
        assertEquals("456", decrypted["id"])
        assertEquals("Minimal Entry", decrypted["title"])
        assertEquals("user", decrypted["username"])
        assertEquals("pass", decrypted["password"])
        assertNull(decrypted["url"])
        assertNull(decrypted["notes"])
        assertNull(decrypted["folder"])
    }

    @Test
    fun entryEncryption_withTamperedCiphertextFails() {
        val vaultKey = engine.generateVaultKey()
        engine.setCachedVaultKey(vaultKey)
        val (encryptedData, iv) = engine.encryptEntry(1L, "Title", "user", "pass", null, null, null)
        val encryptedBytes = Base64.getDecoder().decode(encryptedData)
        encryptedBytes[0] = (encryptedBytes[0].toInt() xor 0xFF).toByte()
        val tampered = Base64.getEncoder().encodeToString(encryptedBytes)
        try {
            engine.decryptEntry(tampered, iv)
            fail("Expected exception when decrypting tampered data")
        } catch (e: Exception) {
            val isGcmFailure = e is javax.crypto.AEADBadTagException ||
                    e is javax.crypto.BadPaddingException ||
                    e is javax.crypto.IllegalBlockSizeException ||
                    e.cause?.javaClass?.simpleName?.contains("AEAD") == true
            assertTrue("Expected GCM authentication failure, got: ${e.javaClass.simpleName}", isGcmFailure)
        }
    }

    @Test
    fun clearCachedVaultKey_preventsEncryption() {
        engine.generateVaultKey()
        engine.clearCachedVaultKey()
        try {
            engine.encryptEntry(1L, "Title", "user", "pass", null, null, null)
            fail("Expected exception when vault key not available")
        } catch (e: IllegalStateException) {
            assertTrue(e.message!!.contains("Vault key not available"))
        }
    }

    // ===== Argon2-Only Tests (require JNI, skipped in JVM unit tests) =====
    // These tests verify Argon2id key derivation. Run on Android device via:
    //   ./gradlew :app:connectedAndroidTest
    // Or manually verify by checking backend tests pass (same Argon2 implementation).

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun deriveKek_producesDeterministicOutput() {
        val kek1 = engine.deriveKekBase64(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val kek2 = engine.deriveKekBase64(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        assertEquals("KEK derivation must be deterministic", kek1, kek2)
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun deriveKek_produces32ByteOutput() {
        val kekBytes = engine.deriveKekForPassword(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        assertEquals("KEK must be 32 bytes (256 bits)", 32, kekBytes.size)
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun deriveKek_differentPasswordProducesDifferentOutput() {
        val kek1 = engine.deriveKekBase64(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val kek2 = engine.deriveKekBase64("DifferentPassword!", TEST_ENCRYPTION_SALT_BASE64)
        assertNotEquals("Different passwords must produce different KEKs", kek1, kek2)
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun deriveKek_differentSaltProducesDifferentOutput() {
        val differentSalt = Base64.getEncoder().encodeToString(ByteArray(16) { it.toByte() })
        val kek1 = engine.deriveKekBase64(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val kek2 = engine.deriveKekBase64(TEST_PASSWORD, differentSalt)
        assertNotEquals("Different salts must produce different KEKs", kek1, kek2)
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun kekAndVaultKey_areDifferentKeys() {
        val kek = engine.deriveKekForPassword(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val vaultKey = Base64.getDecoder().decode(TEST_VAULT_KEY_BASE64)
        assertFalse("KEK and vaultKey must be different values", kek.contentEquals(vaultKey))
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun wrapVaultKey_producesOutputLongerThanInput() {
        val kek = engine.deriveKekForPassword(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val vaultKey = engine.generateVaultKey()
        val wrapped = engine.wrapVaultKeyWithKek(vaultKey, kek)
        val wrappedBytes = Base64.getDecoder().decode(wrapped)
        assertTrue("Wrapped key must be longer due to IV prefix", wrappedBytes.size > 32)
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun wrapVaultKey_producesUniqueOutputEachTime() {
        val kek = engine.deriveKekForPassword(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val wrapped1 = engine.wrapVaultKeyWithKek(TEST_VAULT_KEY_BASE64, kek)
        val wrapped2 = engine.wrapVaultKeyWithKek(TEST_VAULT_KEY_BASE64, kek)
        assertNotEquals("Same inputs must produce different wrapped keys due to random IV", wrapped1, wrapped2)
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun unwrapVaultKey_roundTripsCorrectly() {
        val kek = engine.deriveKekForPassword(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val vaultKey = engine.generateVaultKey()
        val wrapped = engine.wrapVaultKeyWithKek(vaultKey, kek)
        val unwrapped = engine.unwrapVaultKeyWithKek(wrapped, kek)
        assertEquals("Unwrap must recover original vault key", vaultKey, unwrapped)
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun unwrapVaultKey_withWrongKekThrows() {
        val correctKek = engine.deriveKekForPassword(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val wrongKek = engine.deriveKekForPassword("WrongPassword!", TEST_ENCRYPTION_SALT_BASE64)
        val wrapped = engine.wrapVaultKeyWithKek(TEST_VAULT_KEY_BASE64, correctKek)
        try {
            engine.unwrapVaultKeyWithKek(wrapped, wrongKek)
            fail("Expected exception when unwrapping with wrong KEK")
        } catch (e: Exception) {
            val isGcmFailure = e is javax.crypto.AEADBadTagException ||
                    e is javax.crypto.BadPaddingException ||
                    e is javax.crypto.IllegalBlockSizeException
            assertTrue("Expected GCM authentication failure", isGcmFailure)
        }
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun unwrapVaultKey_withTamperedDataThrows() {
        val kek = engine.deriveKekForPassword(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64)
        val wrapped = engine.wrapVaultKeyWithKek(TEST_VAULT_KEY_BASE64, kek)
        val wrappedBytes = Base64.getDecoder().decode(wrapped)
        wrappedBytes[12] = (wrappedBytes[12].toInt() xor 0xFF).toByte()
        val tampered = Base64.getEncoder().encodeToString(wrappedBytes)
        try {
            engine.unwrapVaultKeyWithKek(tampered, kek)
            fail("Expected exception when unwrapping tampered data")
        } catch (e: Exception) {
            val isGcmFailure = e is javax.crypto.AEADBadTagException ||
                    e is javax.crypto.BadPaddingException ||
                    e is javax.crypto.IllegalBlockSizeException
            assertTrue("Expected GCM authentication failure", isGcmFailure)
        }
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun fullRegistrationFlow() {
        val encryptionSalt = TEST_ENCRYPTION_SALT_BASE64
        val vaultKey = engine.generateVaultKey()
        val kek = engine.deriveKekForPassword(TEST_PASSWORD, encryptionSalt)
        val wrappedVaultKey = engine.wrapVaultKeyWithKek(vaultKey, kek)
        val unwrappedVaultKey = engine.unwrapVaultKeyWithKek(wrappedVaultKey, kek)
        assertEquals("Must be able to recover vault key from wrapped form", vaultKey, unwrappedVaultKey)
    }

    @Test @Ignore("Requires Argon2 JNI native library — run on Android device or emulator")
    fun passwordChangeFlow() {
        val encryptionSalt = TEST_ENCRYPTION_SALT_BASE64
        val oldKek = engine.deriveKekForPassword("OldPassword123!", encryptionSalt)
        val newKek = engine.deriveKekForPassword("NewPassword456!", encryptionSalt)
        val vaultKey = engine.generateVaultKey()
        val wrappedWithOld = engine.wrapVaultKeyWithKek(vaultKey, oldKek)
        val unwrappedVaultKey = engine.unwrapVaultKeyWithKek(wrappedWithOld, oldKek)
        val reWrappedWithNew = engine.wrapVaultKeyWithKek(unwrappedVaultKey, newKek)
        assertEquals("Must be able to unwrap with old KEK", vaultKey, unwrappedVaultKey)
        assertNotEquals("Re-wrapping with new KEK must produce different output", wrappedWithOld, reWrappedWithNew)
        val reUnwrapped = engine.unwrapVaultKeyWithKek(reWrappedWithNew, newKek)
        assertEquals("Must be able to unwrap with new KEK after password change", vaultKey, reUnwrapped)
    }
}
