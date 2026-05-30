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
        assertNotNull(got)
        assertEquals(44, got.toKString().length, "auth hash must be 44 chars")
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
        assertNotNull(got)
        assertTrue(got.toKString().length > 20, "KEK base64 length must be reasonable")
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
