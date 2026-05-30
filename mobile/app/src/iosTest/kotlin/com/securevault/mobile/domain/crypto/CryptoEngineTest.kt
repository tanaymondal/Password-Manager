package com.securevault.mobile.domain.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CryptoEngineTest {

    @Test
    fun goldenVector_authHash_matchesRustAndWasm() {
        val expected = "g8BLWUGxvI3XdtW2Ig4k2QL2brmIBvGTlLJGIhHbnJU="
        val got = SecureVaultCryptoCore.securevault_derive_auth_hash(
            "correct horse battery staple",
            "auth-salt-fixed-string",
            4, 65536, 4
        )
        assertNotNull(got, "auth hash must not be null")
        assertEquals(expected, got as String, "iOS auth_hash must match Rust/WASM golden vector")
    }

    @Test
    fun goldenVector_kek_matchesRustAndWasm() {
        val expected = "504NmZdCQp2PNGAZA5gq3vh1rwcT/pVLXWHDcJlf18w="
        val got = SecureVaultCryptoCore.securevault_derive_kek(
            "correct horse battery staple",
            "MDEyMzQ1Njc4OWFiY2RlZg==",
            4, 65536, 4
        )
        assertNotNull(got, "kek must not be null")
        assertEquals(expected, got as String, "iOS kek must match Rust/WASM golden vector")
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
}
