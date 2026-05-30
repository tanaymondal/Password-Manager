@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.securevault.mobile.domain.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.cinterop.toKString

class CryptoEngineTest {

    @Test
    fun goldenVector_authHash_matchesRust() {
        val mkB64 = SecureVaultCryptoCore.securevault_derive_master_key(
            "correct horse battery staple",
            "YXV0aC1zYWx0LWZpeGVkLXN0cmluZw==",
            3, 98304, 4
        ) ?: error("deriveMasterKey returned null")
        val got = SecureVaultCryptoCore.securevault_derive_auth_hash(mkB64.toKString())
            ?: error("deriveAuthHash returned null")
        assertEquals("8hkvgeWmVKTMnrbsvsrbtj/E5IiFKR7PJzdeijmmcig=", got.toKString(), "auth hash must match Rust")
    }

    @Test
    fun goldenVector_kek_matchesRust() {
        val mkB64 = SecureVaultCryptoCore.securevault_derive_master_key(
            "correct horse battery staple",
            "MDEyMzQ1Njc4OWFiY2RlZg==",
            3, 98304, 4
        ) ?: error("deriveMasterKey returned null")
        val got = SecureVaultCryptoCore.securevault_derive_kek(mkB64.toKString())
            ?: error("deriveKek returned null")
        assertEquals("z5Dul//cRyhNDmSjS8qVN9eqHIk78ZN917oFJj3L38A=", got.toKString(), "kek must match Rust")
    }

    @Test
    fun generateSalt_producesBase64() {
        val engine = CryptoEngine()
        val salt = engine.generateSalt()
        assertNotNull(salt)
        assertTrue(salt.length > 0)
    }

    @Test
    fun generateVaultKey_producesBase64() {
        val engine = CryptoEngine()
        val key = engine.generateVaultKey()
        assertNotNull(key)
        assertTrue(key.length > 0)
    }

    @Test
    fun generateSecureDeviceId_producesHex() {
        val engine = CryptoEngine()
        val id = engine.generateSecureDeviceId()
        assertNotNull(id)
        assertEquals(32, id.length)
    }

    @Test
    fun deriveKek_produces32Bytes() {
        val engine = CryptoEngine()
        val kek = engine.deriveKek("testpassword", "MDEyMzQ1Njc4OWFiY2RlZg==", 3, 8192, 1)
        assertNotNull(kek)
        assertEquals(32, kek.size, "KEK must be 32 bytes")
    }

    @Test
    fun deriveKek_deterministic() {
        val engine = CryptoEngine()
        val kek1 = engine.deriveKek("test", "MDEyMzQ1Njc4OWFiY2RlZg==", 3, 8192, 1)
        val kek2 = engine.deriveKek("test", "MDEyMzQ1Njc4OWFiY2RlZg==", 3, 8192, 1)
        assertTrue(kek1.contentEquals(kek2), "KEK must be deterministic")
    }

    @Test
    fun wrapUnwrapVaultKey_roundTrip() {
        val engine = CryptoEngine()
        val kek = engine.deriveKek("password", "MDEyMzQ1Njc4OWFiY2RlZg==", 3, 8192, 1)
        val vaultKey = engine.generateVaultKey()
        val wrapped = engine.wrapVaultKey(vaultKey, kek)
        assertNotNull(wrapped)
        val unwrapped = engine.unwrapVaultKey(wrapped, kek)
        assertNotNull(unwrapped)
        assertEquals(vaultKey, unwrapped)
    }

    @Test
    fun wrapVaultKey_producesUniqueOutput() {
        val engine = CryptoEngine()
        val kek = engine.deriveKek("password", "MDEyMzQ1Njc4OWFiY2RlZg==", 3, 8192, 1)
        val vk = engine.generateVaultKey()
        val w1 = engine.wrapVaultKey(vk, kek)
        val w2 = engine.wrapVaultKey(vk, kek)
        assertNotNull(w1)
        assertNotNull(w2)
        assertTrue(w1 != w2, "Wrapped keys must differ (random IV)")
    }

    // ── Cross-platform AES-GCM golden vector tests ──

    @Test
    fun goldenVector_wrapVaultKey() {
        val kekB64 = "504NmZdCQp2PNGAZA5gq3vh1rwcT/pVLXWHDcJlf18w="
        val wrappedB64 = "oKGio6Slpqeoqaqr5HHezchyg8dzWdJCk+XMGLZMk70asE0SqeA1rq/ZxqiOHm/fEXwfIT/y2n4NLFHN"
        val expectedVk = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        val got = SecureVaultCryptoCore.securevault_unwrap_vault_key(kekB64, wrappedB64)
            ?: error("unwrapVaultKey returned null")
        assertEquals(expectedVk, got.toKString(), "unwrapped vault key must match golden vector")
    }

    @Test
    fun goldenVector_encryptEntry() {
        val vkB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        val encryptedData = "v1:nToMTDa4ddAQAaXpJRK1sATJKyKwm2AY9XpK412RV0SqFyqPw0dxEX3pdqQrQKGRM282O1j/NRs5P2YuyBWr09vRp0MS0JeFhoyeders9pisZ8LHoOPk2ip89WpgBc3FF2Wrs3TNww=="
        val iv = "oKGio6Slpqeoqaqr"
        val got = SecureVaultCryptoCore.securevault_decrypt_entry(vkB64, encryptedData, iv)
            ?: error("decryptEntry returned null")
        assertEquals("{\"password\":\"hunter2\",\"title\":\"Example\",\"url\":\"https://example.com\",\"username\":\"alice\"}",
            got.toKString(), "decrypted entry must match golden plaintext")
    }

    @Test
    fun goldenVector_encryptField() {
        val vkB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        val ciphertext = "v1:oKGio6Slpqeoqaqrjm0SWSC5MCfL5aobdPsWtGz5Z/PKjqM="
        val got = SecureVaultCryptoCore.securevault_decrypt_field(vkB64, ciphertext)
            ?: error("decryptField returned null")
        assertEquals("hunter2", got.toKString(), "decrypted field must match golden plaintext")
    }
}
