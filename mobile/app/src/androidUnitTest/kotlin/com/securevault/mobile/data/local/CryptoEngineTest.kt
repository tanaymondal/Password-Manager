package com.securevault.mobile.data.local

import org.junit.Assert.*
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import java.util.Base64

class CryptoEngineTest {

    companion object {
        const val TEST_PASSWORD = "TestPassword123!"
        const val TEST_ENCRYPTION_SALT_BASE64 = "dGVzdEVuY3J5cHRpb25TYWx0MTIzNDU="
        const val TEST_VAULT_KEY_BASE64 = "dGVzdFZhdWx0S2V5MTIzNDU2Nzg5MGFiY2RlZmdoaWo="

        @BeforeClass @JvmStatic
        fun loadNativeLibrary() {
            val libPath = findLib()
            assertNotNull("Native lib not found! Tests need: app/src/testNativeLibs/libsecurevault_crypto_core.dylib", libPath)
            System.err.println("Loading native lib: $libPath")
            System.load(libPath)
            // Verify the class loads after library load
            try {
                val c = Class.forName("com.securevault.mobile.data.local.NativeBridge")
                System.err.println("NativeBridge class loaded: ${c.name}")
            } catch (e: Exception) {
                System.err.println("ERROR: NativeBridge class not found: ${e.message}")
            }
            // Verify the native method resolves
            try {
                val m = NativeBridge::class.java.getMethod("nativeDeriveMasterKey", String::class.java, String::class.java, Int::class.java, Int::class.java, Int::class.java)
                System.err.println("NativeBridge method resolved: ${m.name}")
            } catch (e: Exception) {
                System.err.println("ERROR: Cannot resolve native method: ${e.message}")
            }
        }

        private fun findLib(): String? {
            val osName = System.getProperty("os.name", "").lowercase()
            val libFileName = when {
                osName.contains("mac") || osName.contains("darwin") -> "libsecurevault_crypto_core.dylib"
                osName.contains("nix") || osName.contains("nux") -> "libsecurevault_crypto_core.so"
                osName.contains("win") -> "securevault_crypto_core.dll"
                else -> return null
            }
            System.err.println("Working dir: ${java.io.File(".").absolutePath}")
            System.err.println("user.dir: ${System.getProperty("user.dir")}")
            val workingDir = java.io.File(System.getProperty("user.dir", "."))
            val candidates = listOf(
                java.io.File(workingDir, "app/src/testNativeLibs/$libFileName"),
                java.io.File(workingDir, "src/testNativeLibs/$libFileName"),
                java.io.File(workingDir.parentFile, "app/src/testNativeLibs/$libFileName"),
                java.io.File(workingDir.parentFile, "src/testNativeLibs/$libFileName"),
                java.io.File("../crypto-core/target/aarch64-apple-darwin/release/$libFileName"),
            )
            for (f in candidates) {
                System.err.println("  checking: ${f.absolutePath}")
                if (f.exists()) return f.absolutePath
            }
            return null
        }
    }

    // ===== RustCryptoCore API shape tests (JVM, no JNI required) =====

    @Test
    fun rustCryptoCore_classLoads() {
        val className = "com.securevault.mobile.domain.crypto.RustCryptoCore"
        val clazz = Class.forName(className)
        assertNotNull("RustCryptoCore class must be loadable", clazz)
    }

    @Test
    fun rustCryptoCore_hasDeriveAuthHashMethod() {
        val method = Class.forName("com.securevault.mobile.domain.crypto.RustCryptoCore")
            .getDeclaredMethod("deriveAuthHash", String::class.java, String::class.java, Int::class.java, Int::class.java, Int::class.java)
        assertNotNull("RustCryptoCore.deriveAuthHash method must exist", method)
        assertEquals("Return type must be String", String::class.java, method.returnType)
    }

    @Test
    fun rustCryptoCore_hasDeriveKekMethod() {
        val method = Class.forName("com.securevault.mobile.domain.crypto.RustCryptoCore")
            .getDeclaredMethod("deriveKek", String::class.java, String::class.java, Int::class.java, Int::class.java, Int::class.java)
        assertNotNull("RustCryptoCore.deriveKek method must exist", method)
        val returnType = method.returnType
        assertEquals("Return type must be ByteArray", ByteArray::class.java, returnType)
    }

    @Test
    fun rustCryptoCore_hasNativeMethods() {
        val clazz = Class.forName("com.securevault.mobile.domain.crypto.RustCryptoCore")
        val methods = clazz.declaredMethods
        val nativeMethods = methods.filter { java.lang.reflect.Modifier.isNative(it.modifiers) }
        assertTrue("RustCryptoCore must have at least 2 native methods", nativeMethods.size >= 2)
        val nativeNames = nativeMethods.map { it.name }.toSet()
        assertTrue("Must have nativeDeriveMasterKey", nativeNames.contains("nativeDeriveMasterKey"))
        assertTrue("Must have nativeDeriveAuthHash", nativeNames.contains("nativeDeriveAuthHash"))
        assertTrue("Must have nativeDeriveKek", nativeNames.contains("nativeDeriveKek"))
    }

    @Test
    fun rustCryptoCore_ensureLoaded_viaTestHelper() {
        // The NativeTestHelper should have loaded the library in @BeforeClass
        // If the native lib is available, this should succeed without throwing
        try {
            val method = Class.forName("com.securevault.mobile.domain.crypto.RustCryptoCore")
                .getDeclaredMethod("deriveAuthHash", String::class.java, String::class.java, Int::class.java, Int::class.java, Int::class.java)
            // Method exists — no exception means the class loaded successfully
            assertNotNull("deriveAuthHash method exists", method)
        } catch (e: Exception) {
            // If we can't even find the class, that's a real failure
            fail("RustCryptoCore class should be accessible: ${e.message}")
        }
    }

    // ── NativeBridge helpers (new two-step flow) ──

    private fun deriveMk(password: String, saltB64: String, iterations: Int, memory: Int, parallelism: Int): String =
        NativeBridge.nativeDeriveMasterKey(password, saltB64, iterations, memory, parallelism)!!

    private fun nativeAuthHash(password: String, saltB64: String, iterations: Int, memory: Int, parallelism: Int): String {
        val mk = deriveMk(password, saltB64, iterations, memory, parallelism)
        return NativeBridge.nativeDeriveAuthHash(mk)!!
    }

    private fun nativeKek(password: String, saltB64: String, iterations: Int, memory: Int, parallelism: Int): String {
        val mk = deriveMk(password, saltB64, iterations, memory, parallelism)
        return NativeBridge.nativeDeriveKek(mk)!!
    }

    private lateinit var engine: CryptoEngine

    @Before
    fun setUp() {
        engine = CryptoEngine(
            getPassword = { TEST_PASSWORD },
            getEncryptionSalt = { TEST_ENCRYPTION_SALT_BASE64 },
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

    @Test
    fun goldenVector_authHash_matchesRustAndWasm() {
        val expected = "g8BLWUGxvI3XdtW2Ig4k2QL2brmIBvGTlLJGIhHbnJU="
        val got = nativeAuthHash("correct horse battery staple", android.util.Base64.encodeToString("auth-salt-fixed-string".toByteArray(), android.util.Base64.NO_WRAP), 4, 65536, 4)
        assertEquals("Android JNI auth_hash must match Rust/WASM golden vector", expected, got)
    }

    @Test
    fun goldenVector_kek_matchesRustAndWasm() {
        val expected = "504NmZdCQp2PNGAZA5gq3vh1rwcT/pVLXWHDcJlf18w="
        val got = nativeKek("correct horse battery staple", "MDEyMzQ1Njc4OWFiY2RlZg==", 4, 65536, 4)
        assertEquals("Android JNI kek must match Rust/WASM golden vector", expected, got)
    }

    @Test
    fun goldenVector_authHash_worksWithFastParams() {
        val got = nativeAuthHash("correct horse battery staple", android.util.Base64.encodeToString("auth-salt-fixed-string".toByteArray(), android.util.Base64.NO_WRAP), 3, 8192, 1)
        assertNotNull("auth hash with fast params must not be null", got)
        assertEquals("auth hash must be 44 chars (base64 of 32 bytes)", 44, got!!.length)
    }

    @Test
    fun goldenVector_kek_worksWithFastParams() {
        val got = nativeKek("correct horse battery staple", "MDEyMzQ1Njc4OWFiY2RlZg==", 3, 8192, 1)
        assertNotNull("kek with fast params must not be null", got)
        assertEquals("kek base64 must be 44 chars (base64 of 32 bytes)", 44, got!!.length)
    }

    @Test
    fun deriveKek_producesDeterministicOutput() {
        val kek1 = nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1)
        val kek2 = nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1)
        assertEquals("KEK derivation must be deterministic", kek1, kek2)
    }

    @Test
    fun deriveKek_produces32ByteOutput() {
        val kekBytes = Base64.getDecoder().decode(nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1))
        assertEquals("KEK must be 32 bytes (256 bits)", 32, kekBytes.size)
    }

    @Test
    fun deriveKek_differentPasswordProducesDifferentOutput() {
        val kek1 = nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1)
        val kek2 = nativeKek("DifferentPassword!", TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1)
        assertNotEquals("Different passwords must produce different KEKs", kek1, kek2)
    }

    @Test
    fun deriveKek_differentSaltProducesDifferentOutput() {
        val differentSalt = Base64.getEncoder().encodeToString(ByteArray(16) { it.toByte() })
        val kek1 = nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1)
        val kek2 = nativeKek(TEST_PASSWORD, differentSalt, 3, 8192, 1)
        assertNotEquals("Different salts must produce different KEKs", kek1, kek2)
    }

    @Test
    fun kekAndVaultKey_areDifferentKeys() {
        val kek = Base64.getDecoder().decode(nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1))
        val vaultKey = Base64.getDecoder().decode(TEST_VAULT_KEY_BASE64)
        assertFalse("KEK and vaultKey must be different values", kek.contentEquals(vaultKey))
    }

    @Test
    fun wrapVaultKey_producesOutputLongerThanInput() {
        val kek = Base64.getDecoder().decode(nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1))
        val vaultKey = engine.generateVaultKey()
        val wrapped = engine.wrapVaultKeyWithKek(vaultKey, kek)
        val wrappedBytes = Base64.getDecoder().decode(wrapped)
        assertTrue("Wrapped key must be longer due to IV prefix", wrappedBytes.size > 32)
    }

    @Test
    fun wrapVaultKey_producesUniqueOutputEachTime() {
        val kek = Base64.getDecoder().decode(nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1))
        val wrapped1 = engine.wrapVaultKeyWithKek(TEST_VAULT_KEY_BASE64, kek)
        val wrapped2 = engine.wrapVaultKeyWithKek(TEST_VAULT_KEY_BASE64, kek)
        assertNotEquals("Same inputs must produce different wrapped keys due to random IV", wrapped1, wrapped2)
    }

    @Test
    fun unwrapVaultKey_roundTripsCorrectly() {
        val kek = Base64.getDecoder().decode(nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1))
        val vaultKey = engine.generateVaultKey()
        val wrapped = engine.wrapVaultKeyWithKek(vaultKey, kek)
        val unwrapped = engine.unwrapVaultKeyWithKek(wrapped, kek)
        assertEquals("Unwrap must recover original vault key", vaultKey, unwrapped)
    }

    @Test
    fun unwrapVaultKey_withWrongKekThrows() {
        val correctKek = Base64.getDecoder().decode(nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1))
        val wrongKek = Base64.getDecoder().decode(nativeKek("WrongPassword!", TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1))
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

    @Test
    fun unwrapVaultKey_withTamperedDataThrows() {
        val kek = Base64.getDecoder().decode(nativeKek(TEST_PASSWORD, TEST_ENCRYPTION_SALT_BASE64, 3, 8192, 1))
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

    @Test
    fun fullRegistrationFlow() {
        val encryptionSalt = TEST_ENCRYPTION_SALT_BASE64
        val vaultKey = engine.generateVaultKey()
        val kek = Base64.getDecoder().decode(nativeKek(TEST_PASSWORD, encryptionSalt, 3, 8192, 1))
        val wrappedVaultKey = engine.wrapVaultKeyWithKek(vaultKey, kek)
        val unwrappedVaultKey = engine.unwrapVaultKeyWithKek(wrappedVaultKey, kek)
        assertEquals("Must be able to recover vault key from wrapped form", vaultKey, unwrappedVaultKey)
    }

    @Test
    fun passwordChangeFlow() {
        val encryptionSalt = TEST_ENCRYPTION_SALT_BASE64
        val oldKek = Base64.getDecoder().decode(nativeKek("OldPassword123!", encryptionSalt, 3, 8192, 1))
        val newKek = Base64.getDecoder().decode(nativeKek("NewPassword456!", encryptionSalt, 3, 8192, 1))
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
